# HxTP-Go SDK

Official Go SDK of the **HxTP/3.0** — a bit-perfect, HMAC-SHA256 signed messaging protocol for high-security IoT and hardware mesh networks.

## 🚀 Quick Start

```go
import (
    "github.com/hestialabs/hxtp-go/client"
)

func main() {
    // 1. Initialize the Authenticated Client
    c := client.NewClient("https://api.hestialabs.in/api/v1", "your-hxtp-token")

    // 2. Dispatch a command
    resp, err := c.SendCommand("device-uuid", "toggle_light", map[string]interface{}{
        "power": true,
    })
    
    // ... handle response
}
```

## 🛠️ Features
- **MCSS v3.0 Engine:** Full 10-field canonical string builder.
- **7-Step Validation:** Fail-closed protocol pipeline (Timestamp, Nonce, HMAC, etc.).
- **Cloud Handshake:** Native support for Firebase Auth and the HxTP Safety Gateway (2PC).

## 🔐 Security
This SDK follows the ** HxTP v3.0 protocol spec**. All messages are signed with HMAC-SHA256 using a device-local secret. 

For security disclosures, contact [contact@hestialabs.in](mailto:contact@hestialabs.in).



================================================
FILE: go.mod
================================================
module github.com/hestialabs/hxtp-go

go 1.24.4

require golang.org/x/text v0.21.0



================================================
FILE: go.sum
================================================
golang.org/x/text v0.21.0 h1:zyQAAkrwaneQ066sspRyJaG9VNi/YJ1NfzcGB3hZ/qo=
golang.org/x/text v0.21.0/go.mod h1:4IBbMaMmOPCJ8SecivzSH54+73PCFmPWxNTLm+vZkEQ=



================================================
FILE: LICENSE
================================================
MIT License

Copyright (c) 2026 Hestia Labs.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


================================================
FILE: client/client.go
================================================
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hestialabs/hxtp-go/crypto"
	"github.com/hestialabs/hxtp-go/protocol"
)

// Client is the high-level HxTP SDK client.
type Client struct {
	BaseURL string
	Token   string // HxTP API Token (HS256)
	HTTP    *http.Client
}

func NewClient(baseUrl, token string) *Client {
	return &Client{
		BaseURL: baseUrl,
		Token:   token,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) request(method, path string, body interface{}) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	var bodyReader io.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if len(respBody) > 0 {
		json.Unmarshal(respBody, &result)
	} else {
		result = map[string]interface{}{"status": "success"}
	}

	if resp.StatusCode >= 400 {
		return result, fmt.Errorf("API_ERROR: HTTP %d: %v", resp.StatusCode, result["error"])
	}

	return result, nil
}

// ── Observability ──────────────────────────────────────────────────────────

func (c *Client) GetDeviceState(deviceId string) (map[string]interface{}, error) {
	return c.request("GET", fmt.Sprintf("/devices/%s/state", deviceId), nil)
}

func (c *Client) GetDeviceCapabilities(deviceId string) (map[string]interface{}, error) {
	return c.request("GET", fmt.Sprintf("/devices/%s/capabilities", deviceId), nil)
}

func (c *Client) GetDeviceCommandHistory(deviceId string) (map[string]interface{}, error) {
	return c.request("GET", fmt.Sprintf("/devices/%s/commands", deviceId), nil)
}

func (c *Client) GetCommandStatus(commandId string) (map[string]interface{}, error) {
	return c.request("GET", fmt.Sprintf("/commands/%s", commandId), nil)
}

// ── Discovery ──────────────────────────────────────────────────────────────

func (c *Client) ListDevices() (map[string]interface{}, error) {
	return c.request("GET", "/devices", nil)
}

func (c *Client) GetDevice(deviceId string) (map[string]interface{}, error) {
	return c.request("GET", fmt.Sprintf("/devices/%s", deviceId), nil)
}

func (c *Client) ListHomes() (map[string]interface{}, error) {
	return c.request("GET", "/homes", nil)
}

func (c *Client) ListRooms(homeId string) (map[string]interface{}, error) {
	return c.request("GET", fmt.Sprintf("/homes/%s/rooms", homeId), nil)
}

func (c *Client) ListGroups() (map[string]interface{}, error) {
	return c.request("GET", "/groups", nil)
}

// ── Provisioning ───────────────────────────────────────────────────────────

func (c *Client) RegisterDevice(deviceType, homeId string, roomId *string) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"device_type": deviceType,
		"home_id":     homeId,
	}
	if roomId != nil {
		payload["room_id"] = *roomId
	}
	return c.request("POST", "/devices/register", payload)
}

func (c *Client) RotateDeviceSecret(deviceId string) (map[string]interface{}, error) {
	return c.request("POST", fmt.Sprintf("/devices/%s/rotate-secret", deviceId), nil)
}

func (c *Client) RevokeDevice(deviceId string) (map[string]interface{}, error) {
	return c.request("POST", fmt.Sprintf("/devices/%s/revoke", deviceId), nil)
}

// ── Home & Room Management ─────────────────────────────────────────────────

func (c *Client) CreateHome(name string, timezone *string) (map[string]interface{}, error) {
	payload := map[string]interface{}{"home_name": name}
	if timezone != nil {
		payload["timezone"] = *timezone
	}
	return c.request("POST", "/homes", payload)
}

func (c *Client) UpdateHome(homeId string, name *string, timezone *string) (map[string]interface{}, error) {
	payload := map[string]interface{}{}
	if name != nil {
		payload["home_name"] = *name
	}
	if timezone != nil {
		payload["timezone"] = *timezone
	}
	return c.request("PATCH", fmt.Sprintf("/homes/%s", homeId), payload)
}

func (c *Client) DeleteHome(homeId string) (map[string]interface{}, error) {
	return c.request("DELETE", fmt.Sprintf("/homes/%s", homeId), nil)
}

func (c *Client) CreateRoom(homeId, name string) (map[string]interface{}, error) {
	return c.request("POST", fmt.Sprintf("/homes/%s/rooms", homeId), map[string]interface{}{"name": name})
}

func (c *Client) DeleteRoom(homeId, roomId string) (map[string]interface{}, error) {
	return c.request("DELETE", fmt.Sprintf("/homes/%s/rooms/%s", homeId, roomId), nil)
}

// ── Group Management ───────────────────────────────────────────────────────

func (c *Client) CreateGroup(name, slug string, groupType *string) (map[string]interface{}, error) {
	payload := map[string]interface{}{"name": name, "slug": slug}
	if groupType != nil {
		payload["group_type"] = *groupType
	}
	return c.request("POST", "/groups", payload)
}

func (c *Client) AddDevicesToGroup(groupId string, deviceIds []string) (map[string]interface{}, error) {
	return c.request("POST", fmt.Sprintf("/groups/%s/devices", groupId), map[string]interface{}{"device_ids": deviceIds})
}

// ── Firmware ───────────────────────────────────────────────────────────────

func (c *Client) CheckFirmwareUpdate(deviceType, currentVersion string, deviceId *string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/firmware/check?device_type=%s&current_version=%s", deviceType, currentVersion)
	if deviceId != nil {
		path += "&device_id=" + *deviceId
	}
	return c.request("GET", path, nil)
}

// ── Manifests ──────────────────────────────────────────────────────────────

func (c *Client) GetDeviceManifest(deviceId string) (map[string]interface{}, error) {
	return c.request("GET", fmt.Sprintf("/devices/%s/manifest", deviceId), nil)
}

func (c *Client) GetManifestCapabilities() (map[string]interface{}, error) {
	return c.request("GET", "/manifest/capabilities", nil)
}

func (c *Client) GetManifestTypes() (map[string]interface{}, error) {
	return c.request("GET", "/manifest/types", nil)
}

// ── Command Dispatch ───────────────────────────────────────────────────────

func (c *Client) SendCommand(deviceId string, action string, params map[string]interface{}, dryRun bool) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"action": action,
		"params": params,
	}
	if dryRun {
		payload["dry_run"] = true
	}
	return c.request("POST", fmt.Sprintf("/devices/%s/command", deviceId), payload)
}

func (c *Client) SendBatchCommand(deviceIds []string, action string, params map[string]interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"device_ids": deviceIds,
		"action":     action,
		"params":     params,
	}
	return c.request("POST", "/devices/command", payload)
}

func (c *Client) SendRoomCommand(roomId string, action string, params map[string]interface{}, capability *string) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"action": action,
		"params": params,
	}
	if capability != nil {
		payload["capability"] = *capability
	}
	return c.request("POST", fmt.Sprintf("/rooms/%s/command", roomId), payload)
}

func (c *Client) SendGroupCommand(groupSlug string, action string, params map[string]interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"action": action,
		"params": params,
	}
	return c.request("POST", fmt.Sprintf("/groups/%s/command", groupSlug), payload)
}

func (c *Client) ConfirmCommand(deviceId string, dryRunToken string) (map[string]interface{}, error) {
	return c.request("POST", fmt.Sprintf("/devices/%s/command/confirm", deviceId), map[string]interface{}{"token": dryRunToken})
}

// SignMessage helper for standalone protocol signing (parity with hxtp-py/js sign).
func SignMessage(msg map[string]interface{}, secretHex string) (string, error) {
	message := protocol.Message{
		Version:        fmt.Sprint(msg["version"]),
		DeviceId:       fmt.Sprint(msg["device_id"]),
		ClientId:       fmt.Sprint(msg["client_id"]),
		MessageId:      fmt.Sprint(msg["message_id"]),
		RequestId:      fmt.Sprint(msg["request_id"]),
		Nonce:          fmt.Sprint(msg["nonce"]),
		MessageType:    fmt.Sprint(msg["message_type"]),
		PayloadHash:    fmt.Sprint(msg["payload_hash"]),
	}
	if v, ok := msg["sequence_number"].(int64); ok {
		message.SequenceNumber = v
	} else if v, ok := msg["sequence_number"].(int); ok {
		message.SequenceNumber = int64(v)
	} else if v, ok := msg["sequence_number"].(float64); ok {
		message.SequenceNumber = int64(v)
	}
	if v, ok := msg["timestamp"].(int64); ok {
		message.Timestamp = v
	} else if v, ok := msg["timestamp"].(int); ok {
		message.Timestamp = int64(v)
	} else if v, ok := msg["timestamp"].(float64); ok {
		message.Timestamp = int64(v)
	}
	canonical, err := protocol.BuildCanonical(message)
	if err != nil {
		return "", err
	}

	secret, err := crypto.HexToBytes(secretHex)
	if err != nil {
		return "", err
	}

	return crypto.SignHmacSha256(secret, canonical), nil
}



================================================
FILE: crypto/hmac.go
================================================
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



================================================
FILE: protocol/canonical.go
================================================
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



================================================
FILE: protocol/topics.go
================================================
package protocol

import (
	"fmt"
	"strings"
)

// TopicInfo represents parsed HxTP topic components.
type TopicInfo struct {
	TenantID string
	DeviceID string
	Channel  string
}

// BuildTopic constructs a canonical MQTT topic.
// Format: hxtp/{tenantId}/device/{deviceId}/{channel}
func BuildTopic(tenantID, deviceID, channel string) string {
	return fmt.Sprintf("hxtp/%s/device/%s/%s", tenantID, deviceID, channel)
}

// BuildWildcard constructs a wildcard subscription topic.
func BuildWildcard(channel string) string {
	return fmt.Sprintf("hxtp/+/device/+/%s", channel)
}

// BuildFullWildcard constructs a wildcard for all channels.
func BuildFullWildcard() string {
	return "hxtp/+/device/+/#"
}

// ParseTopic decomposes an MQTT topic string into components.
func ParseTopic(topic string) (*TopicInfo, error) {
	parts := strings.Split(topic, "/")
	if len(parts) < 5 || parts[0] != "hxtp" || parts[2] != "device" {
		return nil, fmt.Errorf("invalid HxTP topic format: %s", topic)
	}

	return &TopicInfo{
		TenantID: parts[1],
		DeviceID: parts[3],
		Channel:  strings.Join(parts[4:], "/"),
	}, nil
}



================================================
FILE: protocol/types.go
================================================
package protocol

// MessageType defines the HxTP message types.
const (
	MessageTypeState     = "state"
	MessageTypeCommand   = "command"
	MessageTypeHeartbeat = "heartbeat"
	MessageTypeTelemetry = "telemetry"
	MessageTypeOTA       = "ota"
	MessageTypeAck       = "ack"
	MessageTypeError     = "error"
	MessageTypeHello     = "hello"
)

// Channel defines the MQTT topic channel segments.
const (
	ChannelState     = "state"
	ChannelCmd       = "cmd"
	ChannelCmdAck    = "cmd_ack"
	ChannelHello     = "hello"
	ChannelHeartbeat = "heartbeat"
	ChannelOTA       = "ota"
	ChannelOTAStatus = "ota_status"
	ChannelTelemetry = "telemetry"
)



================================================
FILE: validation/pipeline.go
================================================
package validation

import (
	"time"

	"github.com/hestialabs/hxtp-go/crypto"
	"github.com/hestialabs/hxtp-go/protocol"
)

// Protocol Constants
const (
	ProtocolVersion  = "HxTP/3.1"
	LegacyVersion    = "HxTP/3.0"
	MaxMessageAgeSec = 30
	TimestampSkewSec = 5
	MaxPayloadBytes  = 16384
	SecretHexLength  = 64
	NonceTTLSec      = 60
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
	if msg.Version != ProtocolVersion && msg.Version != LegacyVersion {
		return ValidationResult{OK: false, Step: StepVersion, Code: "VERSION_MISMATCH", Reason: "unsupported protocol version"}
	}

	// 2. Timestamp Freshness
	ts := msg.Timestamp
	// Parity with Embedded SDK: handle both seconds and milliseconds
	if ts > 1000000000000 {
		ts = ts / 1000
	}

	age := now - ts
	// 30s expiration window
	if age > MaxMessageAgeSec {
		return ValidationResult{OK: false, Step: StepTimestamp, Code: "TIMESTAMP_EXPIRED", Reason: "message too old (>30s)"}
	}
	// ±5s drift allowance for future-dated messages
	if age < -TimestampSkewSec {
		return ValidationResult{OK: false, Step: StepTimestamp, Code: "TIMESTAMP_FUTURE", Reason: "clock drift exceeded (±5s)"}
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
	paramsCanonical, err := protocol.CanonicalParamsJSON(msg.Params)
	if err != nil {
		return ValidationResult{OK: false, Step: StepPayloadHash, Code: "CANONICAL_BUILD_FAILED", Reason: err.Error()}
	}
	computedHash := crypto.ComputeSha256Hex(paramsCanonical)
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



================================================
FILE: .github/workflows/test.yml
================================================
name: Go SDK CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      - name: Build
        run: go build -v ./...
      - name: Test
        run: go test -v ./...


