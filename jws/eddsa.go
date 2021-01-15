package jws

import (
	"crypto/ed25519"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

func newEdDSASigner(alg jwa.SignatureAlgorithm) (Signer, error) {
	if alg != jwa.EdDSA {
		return nil, errors.Errorf(`unsupported EdDSA signature algorithm %s`, alg)
	}
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

func newEdDSAVerifier(alg jwa.SignatureAlgorithm) (Verifier, error) {
	if alg != jwa.EdDSA {
		return nil, errors.Errorf(`unsupported EdDSA signature algorithm %s`, alg)
	}
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
