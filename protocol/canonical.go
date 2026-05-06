package protocol

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"
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

// Message defines the fields required for the MCSS v3.0 canonical string.
// Maintained for backward compatibility and type safety.
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

// BuildCanonical generates the deterministic pipe-separated canonical string (MCSS v3.0).
func BuildCanonical(msg Message) (string, error) {
	return strings.Join([]string{
		msg.Version,
		msg.DeviceId,
		msg.ClientId,
		msg.MessageId,
		msg.RequestId,
		fmt.Sprintf("%d", msg.SequenceNumber),
		fmt.Sprintf("%d", msg.Timestamp),
		msg.Nonce,
		msg.MessageType,
		msg.PayloadHash,
	}, "|"), nil
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
		f := val.(float64)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return "", fmt.Errorf("CANONICAL_ERROR: Non-finite number")
		}
		// Bit-perfect cross-platform number strategy: Canonical Decimal String
		s := fmt.Sprintf("%.20f", f)
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
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
