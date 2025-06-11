package jwsbb

import (
	"crypto/ed25519"

	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/jwx/v3/internal/tokens"
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

func sign[K any](payload, hdr []byte, signer Signer[K], encoder Base64Encoder, encodePayload bool, key K) ([]byte, error) {
	buf := pool.ByteSlice().GetCapacity(len(payload) + len(hdr) + 1)

	buf = encoder.AppendEncode(buf, hdr)
	buf = append(buf, tokens.Period)
	if encodePayload {
		buf = encoder.AppendEncode(buf, payload)
	} else {
		buf = append(buf, payload...)
	}

	defer pool.ByteSlice().Put(buf)
	return signer.Sign(buf, key)
}
