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

const akpPrivateZKey = "z"

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
		case AKPPrivKey, akpPrivateZKey:
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

// akpThumbprint hashes the canonical JSON form defined by RFC 7638 §3.2
// for AKP keys: the required members {alg, kty, pub} in lexicographic order.
// RFC 9802 makes alg a required thumbprint input for AKP because pub is
// algorithm-scoped — omitting alg would break cross-implementation kid
// lookup.
func akpThumbprint(hash crypto.Hash, alg, pub string) []byte {
	h := hash.New()
	fmt.Fprintf(h, `{"alg":%q,"kty":"AKP","pub":%q}`, alg, pub)
	return h.Sum(nil)
}

// Thumbprint returns the RFC 7638 thumbprint of this AKP key.
//
// AKP keys hash the canonical JSON form `{alg, kty, pub}` per RFC 9802 §7
// — different from the per-kty schemas RFC 7638 §3.2 defines for RSA, EC,
// and oct. Both `alg` and `pub` are required at thumbprint time; an
// error is returned if `alg` has not been set on the key. Other key
// types tolerate a missing `alg` because their canonical thumbprint
// input doesn't include it.
func (k *akpPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	if err := availableHash(hash); err != nil {
		return nil, err
	}
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.pub == nil {
		return nil, fmt.Errorf(`missing "pub" field`)
	}
	if k.algorithm == nil {
		return nil, fmt.Errorf(`missing "alg" field (required for AKP thumbprint)`)
	}
	return akpThumbprint(hash, (*k.algorithm).String(), base64.EncodeToString(k.pub)), nil
}

// Thumbprint returns the RFC 7638 thumbprint of this AKP key.
//
// The thumbprint is computed over the public components only, so the
// returned value is identical to that of the corresponding
// [akpPublicKey]. AKP keys hash the canonical JSON form `{alg, kty, pub}`
// per RFC 9802 §7; both `alg` and `pub` are required at thumbprint time.
func (k *akpPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	if err := availableHash(hash); err != nil {
		return nil, err
	}
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.pub == nil {
		return nil, fmt.Errorf(`missing "pub" field`)
	}
	if k.algorithm == nil {
		return nil, fmt.Errorf(`missing "alg" field (required for AKP thumbprint)`)
	}
	return akpThumbprint(hash, (*k.algorithm).String(), base64.EncodeToString(k.pub)), nil
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
