package verify

import (
	"crypto/ed25519"

	"github.com/pkg/errors"
)

func newEdDSA() (*EdDSAVerifier, error) {
	return &EdDSAVerifier{}, nil
}

func (v EdDSAVerifier) Verify(payload, signature []byte, keyIf interface{}) (err error) {
	switch key := keyIf.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(key, payload, signature) {
			return errors.New(`failed to match EdDSA signature`)
		}
		return nil
	default:
		return errors.Errorf(`invalid key type %T`, keyIf)
	}
}
