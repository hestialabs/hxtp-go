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
