package jwk

import (
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

func init() {
	// Register probe field for "priv" so the parser can distinguish
	// AKP public keys from AKP private keys (which use "priv" instead of "d").
	if err := RegisterProbeField[json.RawMessage]("Priv", "priv"); err != nil {
		panic(fmt.Errorf("jwk/akp: failed to register probe for 'priv' field: %w", err))
	}
}

var normalizedAKP KeyKind

func init() {
	normalizedAKP = KeyKind(jwa.AKP().String()).normalize()
}

func akpKeyKind(algfn func() (jwa.KeyAlgorithm, bool)) KeyKind {
	if alg, ok := algfn(); ok {
		return KeyKind(jwa.AKP().String() + ":" + alg.String()).normalize()
	}
	return normalizedAKP
}

func (k *akpPublicKey) KeyKind() KeyKind  { return akpKeyKind(k.Algorithm) }
func (k *akpPrivateKey) KeyKind() KeyKind { return akpKeyKind(k.Algorithm) }

func makeAKPPublicKey(src Key) (Key, error) {
	newKey := newAKPPublicKey()
	for _, k := range src.Keys() {
		switch k {
		case AKPPrivKey:
			continue
		default:
			v, ok := src.Field(k)
			if !ok {
				return nil, fmt.Errorf(`failed to get field %q`, k)
			}
			if err := newKey.Set(k, v); err != nil {
				return nil, fmt.Errorf(`failed to set field %q: %w`, k, err)
			}
		}
	}
	return newKey, nil
}

func (k *akpPublicKey) PublicKey() (Key, error) {
	return makeAKPPublicKey(k)
}

func (k *akpPrivateKey) PublicKey() (Key, error) {
	return makeAKPPublicKey(k)
}

func akpThumbprint(hash crypto.Hash, pub string) []byte {
	h := hash.New()
	fmt.Fprint(h, `{"kty":"AKP","pub":"`)
	fmt.Fprint(h, pub)
	fmt.Fprint(h, `"}`)
	return h.Sum(nil)
}

func (k *akpPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.pub == nil {
		return nil, fmt.Errorf(`missing "pub" field`)
	}
	return akpThumbprint(hash, base64.EncodeToString(k.pub)), nil
}

func (k *akpPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.pub == nil {
		return nil, fmt.Errorf(`missing "pub" field`)
	}
	return akpThumbprint(hash, base64.EncodeToString(k.pub)), nil
}

func (k *akpPublicKey) Validate() error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.pub == nil || len(k.pub) == 0 {
		return NewKeyValidationError(fmt.Errorf(`jwk.AKPPublicKey: missing "pub" field`))
	}
	if k.algorithm == nil {
		return NewKeyValidationError(fmt.Errorf(`jwk.AKPPublicKey: missing "alg" field (required for AKP keys)`))
	}
	return nil
}

func (k *akpPrivateKey) Validate() error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.pub == nil || len(k.pub) == 0 {
		return NewKeyValidationError(fmt.Errorf(`jwk.AKPPrivateKey: missing "pub" field`))
	}
	if k.priv == nil || len(k.priv) == 0 {
		return NewKeyValidationError(fmt.Errorf(`jwk.AKPPrivateKey: missing "priv" field`))
	}
	if k.algorithm == nil {
		return NewKeyValidationError(fmt.Errorf(`jwk.AKPPrivateKey: missing "alg" field (required for AKP keys)`))
	}
	return nil
}

