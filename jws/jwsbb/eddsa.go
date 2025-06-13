package jwsbb

import (
	"crypto/ed25519"
	"fmt"
)

// eddsaSigner implements EdDSA (Ed25519) signature generation.
// EdDSA is a deterministic signature scheme that doesn't require hashing the payload beforehand.
type eddsaSigner struct{}

func (s eddsaSigner) Sign(key ed25519.PrivateKey, payload []byte) ([]byte, error) {
	// Ed25519 signs the raw payload directly
	return ed25519.Sign(key, payload), nil
}

// SignEdDSA generates an EdDSA (Ed25519) signature for the given payload.
// The raw parameter should be the pre-computed signing input (typically header.payload).
// EdDSA is deterministic and doesn't require additional hashing of the input.
func SignEdDSA(key ed25519.PrivateKey, raw []byte) ([]byte, error) {
	return eddsaSigner{}.Sign(key, raw)
}

// eddsaVerifier implements EdDSA (Ed25519) signature verification.
// EdDSA verification is straightforward as it doesn't require hash function specification.
type eddsaVerifier struct{}

// newEdDSAVerifier creates a new EdDSA verifier.
func newEdDSAVerifier() eddsaVerifier {
	return eddsaVerifier{}
}

func (v eddsaVerifier) Verify(key ed25519.PublicKey, buf []byte, signature []byte) error {
	if !ed25519.Verify(key, buf, signature) {
		return fmt.Errorf("invalid EdDSA signature")
	}
	return nil
}

// VerifyEdDSA verifies an EdDSA (Ed25519) signature for the given payload.
// This function verifies the signature using Ed25519 verification algorithm.
// The payload parameter should be the pre-computed signing input (typically header.payload).
// EdDSA is deterministic and provides strong security guarantees without requiring hash function selection.
func VerifyEdDSA(key ed25519.PublicKey, payload, signature []byte) error {
	v := newEdDSAVerifier()
	return v.Verify(key, payload, signature)
}
