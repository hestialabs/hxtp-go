package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hestialabs/hxtp-go/crypto"
	"github.com/hestialabs/hxtp-go/protocol"
	"github.com/hestialabs/hxtp-go/transport"
)

// Client is the high-level protocol-bound HxTP SDK client.
type Client struct {
	Config    ClientConfig
	Transport transport.Transport
	HTTP      *http.Client // Kept for legacy REST fallback and bootstrap
}

type ClientConfig struct {
	BaseURL  string
	Token    string // HxTP API Token (HS256)
	DeviceId string
	ClientId string
	Secret   string // Hex encoded
}

func NewClient(config ClientConfig) *Client {
	return &Client{
		Config: config,
		HTTP:   &http.Client{Timeout: 15 * time.Second},
	}
}

// SetTransport allows switching from REST to native HxTP transports (MQTT/WS).
func (c *Client) SetTransport(t transport.Transport) {
	c.Transport = t
}

func (c *Client) request(method, path string, body interface{}) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s%s", c.Config.BaseURL, path)
	var bodyReader io.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.Config.Token)
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

// ── Authority & Signing ───────────────────────────────────────────────────

// SignMessage implements the HxTP/3.1 version-aware signing pipeline.
// Deterministically chooses between JSON and Pipe-separated canonical forms.
func SignMessage(msg map[string]interface{}, secretHex string) (string, error) {
	version := fmt.Sprint(msg["version"])
	
	message := protocol.Message{
		Version:        version,
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

	var canonical string
	var err error

	// Version-aware mode selection
	if version == "HxTP/3.1" {
		canonical, err = protocol.BuildCanonical(message)
	} else {
		// Fallback to HxTP/3.0 JSON Canonicalization
		canonical, err = protocol.CanonicalJSON(msg)
	}

	if err != nil {
		return "", err
	}

	secret, err := crypto.HexToBytes(secretHex)
	if err != nil {
		return "", err
	}

	return crypto.SignHmacSha256(secret, canonical), nil
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
	// 1. If protocol-native transport is configured, use it
	if c.Transport != nil && c.Transport.State() == transport.StateConnected {
		envelope, err := protocol.BuildEnvelope(deviceId, c.Config.ClientId, "command", params, 0) // TODO: track sequence
		if err != nil {
			return nil, err
		}

		sig, err := SignMessage(envelope.ToMap(), c.Config.Secret)
		if err != nil {
			return nil, err
		}
		envelope.Signature = sig

		payload, _ := json.Marshal(envelope)
		topic := fmt.Sprintf("hxtp/%s/cmd", deviceId)
		
		err = c.Transport.Send(context.Background(), topic, payload)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"ok":         true,
			"message_id": envelope.MessageId,
			"timestamp":  envelope.Timestamp,
			"transport":  "native",
		}, nil
	}

	// 2. Fallback to REST API
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
