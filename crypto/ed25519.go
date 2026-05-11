package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
)

// PublicKeyFromSeed derives the Ed25519 public key from a private key seed hex string.
func PublicKeyFromSeed(privateKeyHex string) (string, error) {
	privBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", err
	}
	if len(privBytes) != ed25519.SeedSize {
		return "", errors.New("invalid Ed25519 private key seed size")
	}
	priv := ed25519.NewKeyFromSeed(privBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub), nil
}

// SignEd25519 signs a message using Ed25519 and returns the hex-encoded signature.
func SignEd25519(privateKeyHex string, data string) (string, error) {
	privBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", err
	}

	if len(privBytes) != ed25519.SeedSize {
		return "", errors.New("invalid Ed25519 private key seed size")
	}

	priv := ed25519.NewKeyFromSeed(privBytes)
	sig := ed25519.Sign(priv, []byte(data))
	return hex.EncodeToString(sig), nil
}

// VerifyEd25519 verifies an Ed25519 signature.
func VerifyEd25519(publicKeyHex string, data string, signatureHex string) (bool, error) {
	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, err
	}

	if len(pubBytes) != ed25519.PublicKeySize {
		return false, errors.New("invalid Ed25519 public key size")
	}

	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, err
	}

	if len(sigBytes) != ed25519.SignatureSize {
		return false, errors.New("invalid Ed25519 signature size")
	}

	return ed25519.Verify(pubBytes, []byte(data), sigBytes), nil
}
