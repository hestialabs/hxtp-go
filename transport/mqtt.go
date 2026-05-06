package transport

import (
	"context"
	"fmt"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// MQTTTransport implements the HxTP-native MQTT transport layer.
// Features: Deterministic ordering, auto-reconnect, and authority-bound message handling.
type MQTTTransport struct {
	client     mqtt.Client
	handler    func(topic string, payload []byte)
	state      State
	stateMu    sync.RWMutex
	
	// Protocol-bound safety layers
	lastSequence int64
	nonceCache   map[string]time.Time
	cacheMu      sync.Mutex
}

func NewMQTTTransport(broker string, clientID string, username string, password string) *MQTTTransport {
	t := &MQTTTransport{
		state:      StateDisconnected,
		nonceCache: make(map[string]time.Time),
	}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(clientID)
	opts.SetUsername(username)
	opts.SetPassword(password)
	opts.SetCleanSession(false) // Resume for persistent sessions
	opts.SetAutoReconnect(true)
	opts.SetConnectRetryInterval(5 * time.Second)
	
	opts.OnConnect = func(c mqtt.Client) {
		t.updateState(StateConnected)
	}
	opts.OnConnectionLost = func(c mqtt.Client, err error) {
		t.updateState(StateDisconnected)
	}

	t.client = mqtt.NewClient(opts)
	return t
}

func (t *MQTTTransport) Connect(ctx context.Context) error {
	t.updateState(StateConnecting)
	token := t.client.Connect()
	if token.WaitTimeout(10*time.Second) && token.Error() != nil {
		t.updateState(StateError)
		return token.Error()
	}
	return nil
}

func (t *MQTTTransport) Disconnect(ctx context.Context) error {
	t.client.Disconnect(250)
	t.updateState(StateDisconnected)
	return nil
}

func (t *MQTTTransport) Send(ctx context.Context, topic string, payload []byte) error {
	token := t.client.Publish(topic, 1, false, payload)
	if token.WaitTimeout(5*time.Second) && token.Error() != nil {
		return token.Error()
	}
	return nil
}

func (t *MQTTTransport) OnMessage(handler func(topic string, payload []byte)) {
	t.handler = handler
}

func (t *MQTTTransport) Subscribe(ctx context.Context, topic string) error {
	token := t.client.Subscribe(topic, 1, func(c mqtt.Client, m mqtt.Message) {
		if t.handler != nil {
			t.handler(m.Topic(), m.Payload())
		}
	})
	if token.WaitTimeout(5*time.Second) && token.Error() != nil {
		return token.Error()
	}
	return nil
}

func (t *MQTTTransport) Unsubscribe(ctx context.Context, topic string) error {
	token := t.client.Unsubscribe(topic)
	if token.WaitTimeout(5*time.Second) && token.Error() != nil {
		return token.Error()
	}
	return nil
}

func (t *MQTTTransport) Capabilities() Capabilities {
	return Capabilities{
		SupportsRequestReply: false,
		SupportsOrdering:      true,
		SupportsQoS:           true,
	}
}

func (t *MQTTTransport) State() State {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return t.state
}

func (t *MQTTTransport) Health() error {
	if !t.client.IsConnected() {
		return fmt.Errorf("MQTT_DISCONNECTED")
	}
	return nil
}

func (t *MQTTTransport) updateState(s State) {
	t.stateMu.Lock()
	defer t.stateMu.Unlock()
	t.state = s
}

// ── Sequence Enforcement & Deduplication ───────────────────────────────

// CheckAndAdvanceSequence enforces monotonic sequence numbers to prevent replay attacks.
func (t *MQTTTransport) CheckAndAdvanceSequence(seq int64) bool {
	if seq <= t.lastSequence && t.lastSequence != 0 {
		return false
	}
	t.lastSequence = seq
	return true
}

// IsNonceReused checks for nonce reuse within a sliding TTL window.
func (t *MQTTTransport) IsNonceReused(nonce string) bool {
	t.cacheMu.Lock()
	defer t.cacheMu.Unlock()
	
	now := time.Now()
	// Clean expired nonces
	for k, v := range t.nonceCache {
		if now.Sub(v) > 60*time.Second {
			delete(t.nonceCache, k)
		}
	}
	
	if _, exists := t.nonceCache[nonce]; exists {
		return true
	}
	
	t.nonceCache[nonce] = now
	return false
}
