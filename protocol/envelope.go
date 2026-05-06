package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// HxTPEnvelope represents a fully signed HxTP message frame.
type HxTPEnvelope struct {
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
	Signature      string                 `json:"signature"`
	Params         map[string]interface{} `json:"params,omitempty"`
}

// BuildEnvelope constructs a HxTP message frame with the required metadata.
// It does NOT sign the message; use client.SignMessage for that.
func BuildEnvelope(deviceId, clientId, messageType string, params map[string]interface{}, sequence int64) (*HxTPEnvelope, error) {
	// 1. Calculate Payload Hash (Deterministic JSON)
	payloadJSON, err := CanonicalParamsJSON(params)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(payloadJSON))
	payloadHash := hex.EncodeToString(hash[:])

	// 2. Build Envelope
	envelope := &HxTPEnvelope{
		Version:        "HxTP/3.1",
		DeviceId:       deviceId,
		ClientId:       clientId,
		MessageId:      uuid.New().String(),
		RequestId:      uuid.New().String(),
		SequenceNumber: sequence,
		Timestamp:      time.Now().UnixMilli(),
		Nonce:          hex.EncodeToString([]byte(uuid.New().String()[:16])),
		MessageType:    messageType,
		PayloadHash:    payloadHash,
		Params:         params,
	}

	return envelope, nil
}

// ToMap converts the envelope to a map for the signing pipeline.
func (e *HxTPEnvelope) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"version":         e.Version,
		"device_id":       e.DeviceId,
		"client_id":       e.ClientId,
		"message_id":      e.MessageId,
		"request_id":      e.RequestId,
		"sequence_number": e.SequenceNumber,
		"timestamp":       e.Timestamp,
		"nonce":           e.Nonce,
		"message_type":    e.MessageType,
		"payload_hash":    e.PayloadHash,
	}
}
