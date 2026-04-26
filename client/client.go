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
	canonical, err := protocol.CanonicalJSON(msg)
	if err != nil {
		return "", err
	}
	
	secret, err := crypto.HexToBytes(secretHex)
	if err != nil {
		return "", err
	}
	
	return crypto.SignHmacSha256(secret, canonical), nil
}
