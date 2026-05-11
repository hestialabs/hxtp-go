package protocol

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// CanonicalMode defines the deterministic serialization strategy.
type CanonicalMode int

const (
	// ModeJSON uses deterministic JSON (HxTP/3.0 and payload_hash).
	ModeJSON CanonicalMode = iota
	// ModePipeV31 uses pipe-separated fields with escape semantics (HxTP/3.1).
	ModePipeV31
)

/**
 * CanonicalJSON implements the deterministic JSON stringifier.
 * - Lexicographical key sorting
 * - Unicode NFC normalization
 * - Numbers converted to strict decimal strings (avoids IEEE-754 divergence)
 * - Domain Separation: Inject "protocol": "hxtp/3.0"
 */
func CanonicalJSON(v any) (string, error) {
	// Top-level domain separation
	if m, ok := v.(map[string]interface{}); ok {
		if _, exists := m["protocol"]; !exists {
			m["protocol"] = "hxtp/3.0"
		}
	}

	return serialize(v, 0)
}

// CanonicalParamsJSON is the payload_hash representation. It intentionally
// does not inject the protocol discriminator because params are action
// arguments, not a full protocol envelope.
func CanonicalParamsJSON(v any) (string, error) {
	if v == nil {
		v = map[string]interface{}{}
	}
	return serialize(v, 0)
}

// EscapeField applies HxTP/3.1 backslash escaping to a field.
func EscapeField(s string) string {
	s = norm.NFC.String(s)
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

// Message defines the fields required for the HxTP canonical string.
type Message struct {
	Version        string                 `json:"version"`
	DeviceId       string                 `json:"device_id"`
	TenantId       string                 `json:"tenant_id"`
	ClientId       string                 `json:"client_id"`
	MessageId      string                 `json:"message_id"`
	RequestId      string                 `json:"request_id"`
	SequenceNumber int64                  `json:"sequence_number"`
	Timestamp      int64                  `json:"timestamp"`
	Nonce          string                 `json:"nonce"`
	MessageType    string                 `json:"message_type"`
	Capability     string                 `json:"capability,omitempty"`
	Action         string                 `json:"action,omitempty"`
	PayloadHash    string                 `json:"payload_hash"`
	Params         map[string]interface{} `json:"params,omitempty"`
}

// BuildCanonical generates the deterministic pipe-separated canonical string (HxTP/3.1).
// Implements mandatory field escaping and NFC normalization.
func BuildCanonical(msg Message) (string, error) {
	fields := []string{
		msg.Version,
		msg.DeviceId,
		msg.TenantId,
		msg.ClientId,
		msg.MessageId,
		msg.RequestId,
		fmt.Sprintf("%d", msg.SequenceNumber),
		fmt.Sprintf("%d", msg.Timestamp),
		msg.Nonce,
		msg.MessageType,
		msg.PayloadHash,
	}

	for i, f := range fields {
		fields[i] = EscapeField(f)
	}

	return strings.Join(fields, "|"), nil
}

func serialize(v interface{}, depth int) (string, error) {
	if depth > 10 {
		return "", fmt.Errorf("CANONICAL_ERROR: Max depth exceeded")
	}

	if v == nil {
		return "null", nil
	}

	switch val := v.(type) {
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil

	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("\"%d\"", val), nil

	case float32, float64:
		var f float64
		if f64, ok := val.(float64); ok {
			f = f64
		} else {
			f = float64(val.(float32))
		}

		if math.IsNaN(f) || math.IsInf(f, 0) {
			return "", fmt.Errorf("CANONICAL_ERROR: Non-finite number")
		}
		// Bit-perfect cross-platform number strategy: Shortest Decimal String
		s := strconv.FormatFloat(f, 'f', -1, 64)
		if s == "" || s == "-0" {
			s = "0"
		}
		return fmt.Sprintf("\"%s\"", s), nil

	case string:
		// NFC Normalization
		normalized := norm.NFC.String(val)
		b, _ := json.Marshal(normalized)
		return string(b), nil

	case []interface{}:
		var parts []string
		for _, item := range val {
			s, err := serialize(item, depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ",") + "]", nil

	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var parts []string
		for _, k := range keys {
			kb, _ := json.Marshal(k)
			vstr, err := serialize(val[k], depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, fmt.Sprintf("%s:%s", string(kb), vstr))
		}
		return "{" + strings.Join(parts, ",") + "}", nil

	default:
		// Use reflection for structs if needed, but for SDK we typically use maps or defined types
		// For now, return error if unknown
		return "", fmt.Errorf("CANONICAL_ERROR: Unsupported type %T", v)
	}
}
