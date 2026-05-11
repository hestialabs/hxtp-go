package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// ComputeSha256Hex computes the lowercase hex SHA-256 digest of the data.
func ComputeSha256Hex(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// ConstantTimeEqual performs a timing-attack-safe comparison of two strings.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// HexToBytes converts a hex string to bytes.
func HexToBytes(h string) ([]byte, error) {
	return hex.DecodeString(h)
}
