package jwk

import (
	"bytes"
	"crypto"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

func init() {
	// Register probe field for "priv" so the parser can distinguish
	// AKP public keys from AKP private keys (which use "priv" instead of "d").
	if err := RegisterProbeField(reflect.StructField{
		Name: "Priv",
		Type: reflect.TypeFor[json.RawMessage](),
		Tag:  `json:"priv,omitempty"`,
	}); err != nil {
		panic(fmt.Errorf("jwk/akp: failed to register probe for 'priv' field: %w", err))
	}

	RegisterKeyImporter(func(raw *mlkem.EncapsulationKey768) (Key, error) {
		k := newAKPPublicKey()
		return k, k.Import(raw)
	})
	RegisterKeyImporter(func(raw *mlkem.EncapsulationKey1024) (Key, error) {
		k := newAKPPublicKey()
		return k, k.Import(raw)
	})
	RegisterKeyImporter(func(raw *mlkem.DecapsulationKey768) (Key, error) {
		k := newAKPPrivateKey()
		return k, k.Import(raw)
	})
	RegisterKeyImporter(func(raw *mlkem.DecapsulationKey1024) (Key, error) {
		k := newAKPPrivateKey()
		return k, k.Import(raw)
	})
	RegisterKeyExporter(KeyKind(jwa.AKP().String()), KeyExportFunc(akpJWKToRaw))
}

func akpKeyKind(algfn func() (jwa.KeyAlgorithm, bool)) KeyKind {
	if alg, ok := algfn(); ok {
		return KeyKind(jwa.AKP().String() + ":" + alg.String())
	}
	return KeyKind(jwa.AKP().String())
}

func (k *akpPublicKey) KeyKind() KeyKind  { return akpKeyKind(k.Algorithm) }
func (k *akpPrivateKey) KeyKind() KeyKind { return akpKeyKind(k.Algorithm) }

func (k *akpPublicKey) Import(rawKeyIf any) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	switch rawKey := rawKeyIf.(type) {
	case *mlkem.EncapsulationKey768:
		k.pub = rawKey.Bytes()
		alg, _ := jwa.KeyAlgorithmFrom("ML-KEM-768")
		k.algorithm = &alg
	case *mlkem.EncapsulationKey1024:
		k.pub = rawKey.Bytes()
		alg, _ := jwa.KeyAlgorithmFrom("ML-KEM-1024")
		k.algorithm = &alg
	default:
		return fmt.Errorf(`unsupported key type for AKP public key: %T`, rawKeyIf)
	}
	return nil
}

func (k *akpPrivateKey) Import(rawKeyIf any) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	switch rawKey := rawKeyIf.(type) {
	case *mlkem.DecapsulationKey768:
		seed := rawKey.Bytes() // 64-byte d || z
		k.priv = make([]byte, 32)
		copy(k.priv, seed[:32]) // d
		k.z = make([]byte, 32)
		copy(k.z, seed[32:]) // z
		k.pub = rawKey.EncapsulationKey().Bytes()
		alg, _ := jwa.KeyAlgorithmFrom("ML-KEM-768")
		k.algorithm = &alg
	case *mlkem.DecapsulationKey1024:
		seed := rawKey.Bytes()
		k.priv = make([]byte, 32)
		copy(k.priv, seed[:32])
		k.z = make([]byte, 32)
		copy(k.z, seed[32:])
		k.pub = rawKey.EncapsulationKey().Bytes()
		alg, _ := jwa.KeyAlgorithmFrom("ML-KEM-1024")
		k.algorithm = &alg
	default:
		return fmt.Errorf(`unsupported key type for AKP private key: %T`, rawKeyIf)
	}
	return nil
}

func makeAKPPublicKey(src Key) (Key, error) {
	newKey := newAKPPublicKey()
	for _, k := range src.Keys() {
		switch k {
		case AKPPrivKey, AKPZKey:
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

func akpJWKToRaw(key Key, _ any) (any, error) {
	extracted, err := extractEmbeddedKey(key, []reflect.Type{
		reflect.TypeFor[AKPPrivateKey](),
		reflect.TypeFor[AKPPublicKey](),
	})
	if err != nil {
		return nil, fmt.Errorf(`jwk.AKP: failed to extract embedded key: %w`, err)
	}

	switch key := extracted.(type) {
	case AKPPrivateKey:
		pub, ok := key.Pub()
		if !ok {
			return nil, fmt.Errorf(`missing "pub" field`)
		}
		priv, ok := key.Priv()
		if !ok {
			return nil, fmt.Errorf(`missing "priv" field`)
		}

		alg, ok := key.Algorithm()
		if !ok {
			return nil, fmt.Errorf(`missing "alg" field`)
		}

		// Reconstruct the 64-byte seed: d || z
		// If z is absent, generate a fresh random z
		z, hasZ := key.Z()

		seed := make([]byte, 64)
		copy(seed[:32], priv)
		if hasZ && len(z) == 32 {
			copy(seed[32:], z)
		} else {
			if _, err := rand.Read(seed[32:]); err != nil {
				return nil, fmt.Errorf(`failed to generate random z: %w`, err)
			}
		}

		switch alg.String() {
		case "ML-KEM-768", "ML-KEM-768+A192KW":
			dk, err := mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				return nil, fmt.Errorf(`failed to construct ML-KEM-768 decapsulation key: %w`, err)
			}
			// Verify pub matches
			if got := dk.EncapsulationKey().Bytes(); !bytes.Equal(got, pub) {
				return nil, fmt.Errorf(`"pub" field does not match key derived from "priv"`)
			}
			return dk, nil
		case "ML-KEM-1024", "ML-KEM-1024+A256KW":
			dk, err := mlkem.NewDecapsulationKey1024(seed)
			if err != nil {
				return nil, fmt.Errorf(`failed to construct ML-KEM-1024 decapsulation key: %w`, err)
			}
			if got := dk.EncapsulationKey().Bytes(); !bytes.Equal(got, pub) {
				return nil, fmt.Errorf(`"pub" field does not match key derived from "priv"`)
			}
			return dk, nil
		default:
			return nil, fmt.Errorf(`unsupported AKP algorithm: %s`, alg)
		}

	case AKPPublicKey:
		pub, ok := key.Pub()
		if !ok {
			return nil, fmt.Errorf(`missing "pub" field`)
		}

		alg, ok := key.Algorithm()
		if !ok {
			return nil, fmt.Errorf(`missing "alg" field`)
		}

		switch alg.String() {
		case "ML-KEM-768", "ML-KEM-768+A192KW":
			return mlkem.NewEncapsulationKey768(pub)
		case "ML-KEM-1024", "ML-KEM-1024+A256KW":
			return mlkem.NewEncapsulationKey1024(pub)
		default:
			return nil, fmt.Errorf(`unsupported AKP algorithm: %s`, alg)
		}

	default:
		return nil, ContinueError()
	}
}

