package jwsbb

import (
	"crypto/ed25519"
	"fmt"
)

// EdDSASigner signs payloads using EdDSA (Ed25519).
type EdDSASigner struct{}

func (s EdDSASigner) Sign(payload []byte, key ed25519.PrivateKey) ([]byte, error) {
	// Ed25519 signs the raw payload directly
	return ed25519.Sign(key, payload), nil
}

func SignEdDSA(payload, hdr []byte, encoder Base64Encoder, encodePayload bool, key ed25519.PrivateKey) ([]byte, error) {
	return sign[ed25519.PrivateKey](payload, hdr, EdDSASigner{}, encoder, encodePayload, key)
}

// EdDSAVerifier verifies EdDSA (Ed25519) signatures.
type EdDSAVerifier struct{}

func (v EdDSAVerifier) Verify(buf []byte, signature []byte, key ed25519.PublicKey) error {
	if !ed25519.Verify(key, buf, signature) {
		return fmt.Errorf("invalid EdDSA signature")
	}
	return nil
}

// VerifyEdDSA verifies the EdDSA (Ed25519) signature for the given payload and header.
func VerifyEdDSA(payload, hdr, signature []byte, encoder Base64Encoder, encodePayload bool, pubKey ed25519.PublicKey) error {
	return verify[ed25519.PublicKey](payload, hdr, signature, EdDSAVerifier{}, encoder, encodePayload, pubKey)
}
