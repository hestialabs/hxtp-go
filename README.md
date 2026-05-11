# HxTP-Go SDK

Official Go SDK of the **HxTP/3.1** — a bit-perfect, Ed25519-signed messaging protocol for high-security IoT and hardware mesh networks.

## 🚀 Quick Start

```go
import (
    "github.com/hestialabs/hxtp-go/client"
    "github.com/hestialabs/hxtp-go/protocol"
)

func main() {
    // 1. Initialize the Protocol-Bound Client
    c := client.NewClient(client.Config{
        BaseURL:  "https://api.hestialabs.in/api/v1",
        Token:    "your-auth-token",
        ClientID: "unique-client-id",
        Secret:   "64-char-hex-private-key",
        Version:  protocol.V31, // Mandatory HxTP/3.1
    })

    // 2. Dispatch a command via native MQTT (optional)
    // c.SetTransport(mqttTransport)

    resp, err := c.SendCommand("device-uuid", "toggle_light", map[string]interface{}{
        "power": true,
    })
    
    // ... handle response
}
```

## 🛠️ Features
- **HxTP/3.1 Core:** Pipe-separated framing with mandatory backslash escaping.
- **Bit-Perfect Parity:** Verified against the cross-language compliance suite.
- **Transport Agnostic:** Pluggable REST, MQTT, and WebSocket layers.
- **7-Step Validation:** Fail-closed protocol pipeline (Timestamp, Nonce, Ed25519 signature, etc.).

## 🔐 Security
This SDK follows the **[HxTP v3.1 protocol spec](../../hxtp/sdk/PROTOCOL_SPEC_V31.md)**. All messages are signed with Ed25519 using the device's private key and normalized using Unicode NFC.

For security disclosures, contact [contact@hestialabs.in](mailto:contact@hestialabs.in).
