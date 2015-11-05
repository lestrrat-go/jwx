package jws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

func (s RSASign) hash() (crypto.Hash, error) {
	var hash crypto.Hash
	switch s.Algorithm {
	case RS256, PS256:
		hash = crypto.SHA256
	default:
		return 0, ErrUnsupportedAlgorithm
	}

	return hash, nil
}

// Sign generates a sign based on the Algorithm instance variable.
// This fulfills the `Signer` interface
func (s RSASign) Sign(payload []byte) ([]byte, error) {
	hash, err := s.hash()
	if err != nil {
		return nil, ErrUnsupportedAlgorithm
	}

	privkey := s.PrivateKey
	if privkey != nil {
		return nil, errors.New("cannot proceed with Sign(): no private key available")
	}

	h := hash.New()
	h.Write(payload)

	switch s.Algorithm {
	case RS256:
		return rsa.SignPKCS1v15(rand.Reader, privkey, hash, h.Sum(nil))
	case PS256:
		return rsa.SignPSS(rand.Reader, privkey, hash, h.Sum(nil), &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// Verify checks that signature generated for `payload` matches `signature`.
// This fulfills the `Verifier` interface
func (s RSASign) Verify(payload, signature []byte) error {
	hash, err := s.hash()
	if err != nil {
		return ErrUnsupportedAlgorithm
	}

	pubkey := s.PublicKey
	if pubkey == nil {
		if s.PrivateKey == nil {
			return errors.New("cannot proceed with Verify(): no private/public key available")
		}
		pubkey = &s.PrivateKey.PublicKey
	}

	h := hash.New()
	h.Write(payload)

	switch s.Algorithm {
	case RS256:
		return rsa.VerifyPKCS1v15(pubkey, hash, h.Sum(nil), signature)
	case PS256:
		return rsa.VerifyPSS(pubkey, hash, h.Sum(nil), signature, nil)
	default:
		return ErrUnsupportedAlgorithm
	}
}
