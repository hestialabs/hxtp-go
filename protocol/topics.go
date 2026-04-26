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
