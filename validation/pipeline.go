package validation

import (
	"time"

	"github.com/hestialabs/hxtp-go/crypto"
	"github.com/hestialabs/hxtp-go/protocol"
)

// FROZEN Protocol Constants
const (
	ProtocolVersion    = "HxTP/3.0"
	MaxMessageAgeSec   = 300
	TimestampSkewSec   = 60
	MaxPayloadBytes    = 16384
	SecretHexLength    = 64
)

// ValidationStep represents a step in the 7-step pipeline.
type ValidationStep string

const (
	StepVersion     ValidationStep = "VERSION_CHECK"
	StepTimestamp   ValidationStep = "TIMESTAMP_CHECK"
	StepPayloadSize ValidationStep = "PAYLOAD_SIZE_CHECK"
	StepNonce       ValidationStep = "NONCE_CHECK"
	StepPayloadHash ValidationStep = "PAYLOAD_HASH_CHECK"
	StepSequence    ValidationStep = "SEQUENCE_CHECK"
	StepSignature   ValidationStep = "SIGNATURE_CHECK"
)

// ValidationResult carries the outcome of a pipeline execution.
type ValidationResult struct {
	OK      bool
	Step    ValidationStep
	Code    string
	Reason  string
	Rotated bool // True if validation passed using the previous secret (rotation window)
}

// Validator handles the stateful parts of validation (Nonce cache, sequence tracking).
type Validator struct {
	lastSequence int64
	nonceCache   map[string]time.Time
}

func NewValidator() *Validator {
	return &Validator{
		nonceCache: make(map[string]time.Time),
	}
}

// ValidateMessage executes the FROZEN 7-step pipeline.
// Supports dual-key fallback for HMAC-SHA256 signature verification.
func (v *Validator) ValidateMessage(msg protocol.Message, payload string, secretHex string, prevSecretHex string, providedSignature string) ValidationResult {
	now := time.Now().Unix()

	// 1. Version Check
	if msg.Version != ProtocolVersion {
		return ValidationResult{OK: false, Step: StepVersion, Code: "VERSION_MISMATCH", Reason: "unsupported protocol version"}
	}

	// 2. Timestamp Freshness
	age := now - msg.Timestamp
	if age > MaxMessageAgeSec {
		return ValidationResult{OK: false, Step: StepTimestamp, Code: "TIMESTAMP_EXPIRED", Reason: "message too old"}
	}
	if msg.Timestamp > now+TimestampSkewSec {
		return ValidationResult{OK: false, Step: StepTimestamp, Code: "TIMESTAMP_FUTURE", Reason: "message from the future"}
	}

	// 3. Payload Size
	if len(payload) > MaxPayloadBytes {
		return ValidationResult{OK: false, Step: StepPayloadSize, Code: "PAYLOAD_TOO_LARGE", Reason: "exceeds 16KB limit"}
	}

	// 4. Nonce Uniqueness
	if _, exists := v.nonceCache[msg.Nonce]; exists {
		return ValidationResult{OK: false, Step: StepNonce, Code: "NONCE_REUSED", Reason: "replay attack detected"}
	}
	v.nonceCache[msg.Nonce] = time.Now()

	// 5. Payload Hash Verification
	computedHash := crypto.ComputeSha256Hex(payload)
	if msg.PayloadHash != "" && !crypto.ConstantTimeEqual(msg.PayloadHash, computedHash) {
		return ValidationResult{OK: false, Step: StepPayloadHash, Code: "HASH_MISMATCH", Reason: "payload hash does not match"}
	}

	// 6. Sequence Monotonicity
	if msg.SequenceNumber <= v.lastSequence && v.lastSequence != 0 {
		return ValidationResult{OK: false, Step: StepSequence, Code: "SEQUENCE_VIOLATION", Reason: "out-of-order sequence"}
	}
	v.lastSequence = msg.SequenceNumber

	// 7. HMAC-SHA256 Signature Verification (with Dual-Key Fallback)
	canonical, err := protocol.BuildCanonical(msg)
	if err != nil {
		return ValidationResult{OK: false, Step: StepSignature, Code: "CANONICAL_BUILD_FAILED", Reason: err.Error()}
	}

	// Try active secret
	secret, err := crypto.HexToBytes(secretHex)
	if err == nil {
		expectedSignature := crypto.SignHmacSha256(secret, canonical)
		if crypto.ConstantTimeEqual(expectedSignature, providedSignature) {
			return ValidationResult{OK: true}
		}
	}

	// Try previous secret (rotation window)
	if prevSecretHex != "" {
		prevSecret, err := crypto.HexToBytes(prevSecretHex)
		if err == nil {
			expectedSignature := crypto.SignHmacSha256(prevSecret, canonical)
			if crypto.ConstantTimeEqual(expectedSignature, providedSignature) {
				return ValidationResult{OK: true, Rotated: true}
			}
		}
	}

	return ValidationResult{OK: false, Step: StepSignature, Code: "SIGNATURE_INVALID", Reason: "signature verification failed"}
}
