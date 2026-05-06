package transport

import (
	"context"
)

// State defines the current connectivity state of the transport.
type State int

const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
	StateError
)

// Capabilities defines the features supported by a specific transport.
type Capabilities struct {
	SupportsRequestReply bool
	SupportsOrdering      bool
	SupportsQoS           bool
}

// Transport defines the required interface for all HxTP transport layers.
// This abstraction ensures authority-agnostic communication across MQTT, WS, and REST.
type Transport interface {
	// Lifecycle
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
	
	// Communication
	Send(ctx context.Context, topic string, payload []byte) error
	OnMessage(handler func(topic string, payload []byte))
	
	// Protocol Negotiation
	Capabilities() Capabilities
	State() State
	Health() error
	
	// High-level semantics (if supported)
	Subscribe(ctx context.Context, topic string) error
	Unsubscribe(ctx context.Context, topic string) error
}

// RequestReplyTransport extends basic Transport for synchronous patterns.
type RequestReplyTransport interface {
	Transport
	Request(ctx context.Context, topic string, payload []byte) ([]byte, error)
}
