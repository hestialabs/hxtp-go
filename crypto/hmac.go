package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// SignHmacSha256 computes the lowercase hex HMAC-SHA256 signature of the data.
// This is the bit-perfect match for hxtp-py and the backend.
func SignHmacSha256(secret []byte, data string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeSha256Hex computes the lowercase hex SHA-256 digest of the data.
// Used for the bit-perfect payload hashing required by MCSS v3.0.
func ComputeSha256Hex(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// ConstantTimeEqual performs a timing-attack-safe comparison of two strings.
// Crucial for signature verification.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// GenerateNonceHex returns a cryptographically secure random hex string.
func GenerateNonceHex(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("CRYPTO_ERROR: Failed to generate random bytes: %v", err)
	}
	return hex.EncodeToString(b), nil
}

// HexToBytes converts a hex string to bytes.
func HexToBytes(h string) ([]byte, error) {
	return hex.DecodeString(h)
}
