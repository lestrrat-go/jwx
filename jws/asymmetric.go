package jws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

	h := hash.New()
	h.Write(payload)

	switch s.Algorithm {
	case RS256:
		return rsa.SignPKCS1v15(rand.Reader, s.PrivateKey, hash, h.Sum(nil))
	case PS256:
		return rsa.SignPSS(rand.Reader, s.PrivateKey, hash, h.Sum(nil), &rsa.PSSOptions{
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

	h := hash.New()
	h.Write(payload)

	switch s.Algorithm {
	case RS256:
		return rsa.VerifyPKCS1v15(&s.PrivateKey.PublicKey, hash, h.Sum(nil), signature)
	case PS256:
		return rsa.VerifyPSS(&s.PrivateKey.PublicKey, hash, h.Sum(nil), signature, nil)
	default:
		return ErrUnsupportedAlgorithm
	}
}
