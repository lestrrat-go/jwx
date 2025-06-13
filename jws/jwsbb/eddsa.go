package jwsbb

import (
	"crypto/ed25519"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
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

func (v eddsaVerifier) Verify(key ed25519.PublicKey, buf []byte, signature []byte) error {
	if !ed25519.Verify(key, buf, signature) {
		return fmt.Errorf("invalid EdDSA signature")
	}
	return nil
}

// VerifyEdDSA verifies an EdDSA (Ed25519) signature for the given payload and header.
// This function constructs the signing input by encoding the header and payload according to JWS specification,
// then verifies the signature using Ed25519 verification algorithm.
// EdDSA is deterministic and provides strong security guarantees without requiring hash function selection.
func VerifyEdDSA(key ed25519.PublicKey, payload, hdr, signature []byte, encoder base64.Encoder, encodePayload bool) error {
	return Verify[ed25519.PublicKey](key, payload, hdr, signature, eddsaVerifier{}, encoder, encodePayload)
}
