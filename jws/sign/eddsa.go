package sign

import (
	"crypto/ed25519"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

func newEdDSA() (Signer, error) {
	return &EdDSASigner{}, nil
}

func (s EdDSASigner) Algorithm() jwa.SignatureAlgorithm {
	return jwa.EdDSA
}

func (s EdDSASigner) Sign(payload []byte, keyif interface{}) ([]byte, error) {
	switch key := keyif.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(key, payload), nil
	default:
		return nil, errors.Errorf(`invalid key type %T`, keyif)
	}
}
