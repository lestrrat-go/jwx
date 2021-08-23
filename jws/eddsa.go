package jws

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"

	"github.com/lestrrat-go/jwx/internal/keyconv"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

func newEdDSASigner() Signer {
	return &EdDSASigner{}
}

func (s EdDSASigner) Algorithm() jwa.SignatureAlgorithm {
	return jwa.EdDSA
}

func (s EdDSASigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	if key == nil {
		return nil, errors.New(`missing private key while signing payload`)
	}

	// The ed25519.PrivateKey object implements crypto.Signer, so we should
	// simply accept a crypto.Signer here.
	signer, ok := key.(crypto.Signer)
	if !ok {
		// This fallback exists for cases when jwk.Key was passed, or
		// users gave us a pointer instead of non-pointer, etc.
		var privkey ed25519.PrivateKey
		if err := keyconv.Ed25519PrivateKey(&privkey, key); err != nil {
			return nil, errors.Wrapf(err, `failed to retrieve ed25519.PrivateKey out of %T`, key)
		}
		signer = privkey
	}
	return signer.Sign(rand.Reader, payload, crypto.Hash(0))
}

func newEdDSAVerifier() Verifier {
	return &EdDSAVerifier{}
}

func (v EdDSAVerifier) Verify(payload, signature []byte, key interface{}) (err error) {
	if key == nil {
		return errors.New(`missing public key while verifying payload`)
	}

	var pubkey ed25519.PublicKey
	if err := keyconv.Ed25519PublicKey(&pubkey, key); err != nil {
		return errors.Wrapf(err, `failed to retrieve ed25519.PublicKey out of %T`, key)
	}
	if !ed25519.Verify(pubkey, payload, signature) {
		return errors.New(`failed to match EdDSA signature`)
	}
	return nil
}
