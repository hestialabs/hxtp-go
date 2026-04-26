package protocol

import (
	"fmt"
	"strings"
)

const CanonicalSeparator = "|"

// Message defines the fields required for the MCSS v3.0 canonical string.
// All 10 fields are mandatory in the FROZEN v3.0 spec.
type Message struct {
	Version        string // version
	DeviceId       string // did
	ClientId       string // cid
	MessageId      string // mid
	RequestId      string // rid
	SequenceNumber int64  // seq
	Timestamp      int64  // ts
	Nonce          string // nonce
	MessageType    string // mtype
	PayloadHash    string // phash
}

// BuildCanonical generates the bit-perfect MCSS v3.0 canonical string.
// Format: version|did|cid|mid|rid|seq|ts|nonce|mtype|phash
func BuildCanonical(msg Message) (string, error) {
	parts := []string{
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
	}

	// Strict validation: No empty fields allowed in v3.0
	for i, part := range parts {
		if part == "" {
			return "", fmt.Errorf("CANONICAL_ERROR: Missing mandatory field at index %d", i)
		}
	}

	return strings.Join(parts, CanonicalSeparator), nil
}
