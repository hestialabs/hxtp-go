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
 * CanonicalJSON implements the Production Grade deterministic JSON stringifier.
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

	return serialize(v)
}

// Message defines the fields required for the MCSS v3.0 canonical string.
// Maintained for backward compatibility and type safety.
type Message struct {
	Version        string                 `json:"version"`
	DeviceId       string                 `json:"device_id"`
	ClientId       string                 `json:"client_id"`
	MessageId      string                 `json:"message_id"`
	RequestId      string                 `json:"request_id"`
	SequenceNumber int64                  `json:"sequence_number"`
	Timestamp      int64                  `json:"timestamp"`
	Nonce          string                 `json:"nonce"`
	MessageType    string                 `json:"message_type"`
	PayloadHash    string                 `json:"payload_hash"`
	Params         map[string]interface{} `json:"params,omitempty"`
}

// BuildCanonical generates the Production Grade canonical JSON string.
func BuildCanonical(msg Message) (string, error) {
	// Convert struct to map for CanonicalJSON
	m := map[string]interface{}{
		"version":         msg.Version,
		"device_id":       msg.DeviceId,
		"client_id":       msg.ClientId,
		"message_id":      msg.MessageId,
		"request_id":      msg.RequestId,
		"sequence_number": msg.SequenceNumber,
		"timestamp":       msg.Timestamp,
		"nonce":           msg.Nonce,
		"message_type":    msg.MessageType,
		"payload_hash":    msg.PayloadHash,
	}
	if msg.Params != nil {
		m["params"] = msg.Params
	}

	return CanonicalJSON(m)
}

func serialize(v interface{}) (string, error) {
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
			s, err := serialize(item)
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
			vstr, err := serialize(val[k])
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
