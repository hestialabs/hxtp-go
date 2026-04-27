# HxTP-Go SDK

Official Go SDK of the **HxTP/3.0** — a bit-perfect, HMAC-SHA256 signed messaging protocol for high-security IoT and hardware mesh networks.

## 🚀 Quick Start

```go
import (
    "github.com/hestialabs/hxtp-go/client"
)

func main() {
    // 1. Initialize the Authenticated Client
    c := client.NewClient("https://api.hestialabs.in/api/v1", "your-neon-jwt")

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
- **Cloud Handshake:** Native support for Neon Auth and the HxTP Safety Gateway (2PC).

## 🔐 Security
This SDK follows the ** HxTP v3.0 protocol spec**. All messages are signed with HMAC-SHA256 using a device-local secret. 

For security disclosures, contact [contact@hestialabs.in](mailto:contact@hestialabs.in).
