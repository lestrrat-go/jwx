//go:build jwx_dilithium
// +build jwx_dilithium

package jwk

import (
	"crypto"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

func dilithiumThumbprint(hash crypto.Hash, alg string, x []byte) []byte {
	h := hash.New()
	fmt.Fprintf(h, `{"kty":"MLWE","alg":%q,"x":`, alg)
	fmt.Fprint(h, base64.EncodeToString(x))
	fmt.Fprint(h, `"}`)
	return h.Sum(nil)
}

func (k *dilithiumPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.x == nil {
		return nil, fmt.Errorf(`missing x value`)
	}

	return dilithiumThumbprint(hash, (*k.algorithm).String(), k.x), nil
}

func (k *dilithiumPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.x == nil {
		return nil, fmt.Errorf(`missing x value`)
	}

	return dilithiumThumbprint(hash, (*k.algorithm).String(), k.x), nil
}

func validateDilithiumKey(key interface {
	Algorithm() (jwa.KeyAlgorithm, bool)
	X() ([]byte, bool)
}, checkPrivate bool) error {
	x, ok := key.X()
	if !ok {
		return fmt.Errorf(`missing "x" value`)
	}
	if len(x) == 0 {
		return fmt.Errorf(`invalid "x" value`)
	}

	alg, ok := key.Algorithm()
	if !ok {
		return fmt.Errorf(`missing "alg" value`)
	}

	var expectedAlgLen int
	switch alg {
	case jwa.CRYDI2():
		expectedAlgLen = 1312
	case jwa.CRYDI3():
		expectedAlgLen = 1959
	case jwa.CRYDI5():
		expectedAlgLen = 2592
	default:
		return fmt.Errorf(`invalid "alg" value %q`, alg)
	}
	if len(x) != expectedAlgLen {
		return fmt.Errorf(`invalid "x" length (%d)`, len(x))
	}

	if checkPrivate {
		if priv, ok := key.(keyWithD); ok {
			if d, ok := priv.D(); !ok || len(d) == 0 {
				return fmt.Errorf(`missing "d" value`)
			}
		} else {
			return fmt.Errorf(`missing "d" value`)
		}
	}
	return nil
}

func (k *dilithiumPrivateKey) Validate() error {
	if err := validateDilithiumKey(k, true); err != nil {
		return NewKeyValidationError(fmt.Errorf(`jwk.DilithiumPrivateKey: %w`, err))
	}
	return nil
}

func (k *dilithiumPublicKey) Validate() error {
	if err := validateDilithiumKey(k, false); err != nil {
		return NewKeyValidationError(fmt.Errorf(`jwk.DilithiumPublicKey: %w`, err))
	}
	return nil
}

func (k *dilithiumPublicKey) PublicKey() (Key, error) {
	return makeDilithiumPublicKey(k)
}

func (k *dilithiumPrivateKey) PublicKey() (Key, error) {
	return makeDilithiumPublicKey(k)
}

func makeDilithiumPublicKey(src Key) (Key, error) {
	newKey := newDilithiumPublicKey()

	// Iterate and copy everything except for the bits that should not be in the public key
	for _, k := range src.Keys() {
		switch k {
		case DilithiumDKey:
			continue
		default:
			var v interface{}
			if err := src.Get(k, &v); err != nil {
				return nil, fmt.Errorf(`dilithium: makeDilithiumPublicKey: failed to get field %q: %w`, k, err)
			}

			if err := newKey.Set(k, v); err != nil {
				return nil, fmt.Errorf(`dilithium: makeDilithiumPublicKey: failed to set field %q: %w`, k, err)
			}
		}
	}
	return newKey, nil
}
