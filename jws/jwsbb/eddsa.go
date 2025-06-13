package jwsbb

import (
	"crypto/ed25519"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
)

// EdDSASigner signs payloads using EdDSA (Ed25519).
type EdDSASigner struct{}

func (s EdDSASigner) Sign(key ed25519.PrivateKey, payload []byte) ([]byte, error) {
	// Ed25519 signs the raw payload directly
	return ed25519.Sign(key, payload), nil
}

func SignEdDSA(key ed25519.PrivateKey, raw []byte) ([]byte, error) {
	return EdDSASigner{}.Sign(key, raw)
}

// EdDSAVerifier verifies EdDSA (Ed25519) signatures.
type EdDSAVerifier struct{}

func (v EdDSAVerifier) Verify(key ed25519.PublicKey, buf []byte, signature []byte) error {
	if !ed25519.Verify(key, buf, signature) {
		return fmt.Errorf("invalid EdDSA signature")
	}
	return nil
}

// VerifyEdDSA verifies the EdDSA (Ed25519) signature for the given payload and header.
func VerifyEdDSA(key ed25519.PublicKey, payload, hdr, signature []byte, encoder base64.Encoder, encodePayload bool) error {
	return Verify[ed25519.PublicKey](key, payload, hdr, signature, EdDSAVerifier{}, encoder, encodePayload)
}
