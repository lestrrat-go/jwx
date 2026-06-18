package jwk

import (
	"crypto"
	"fmt"
	"reflect"
	"slices"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

func init() {
	panicOnRegistrationError(RegisterKeyExporter(KeyKind(jwa.OctetSeq().String()), KeyExportFunc(octetSeqToRaw)))
}

func (k *symmetricKey) Import(rawKey []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if len(rawKey) == 0 {
		return fmt.Errorf(`non-empty []byte key required`)
	}

	k.octets = slices.Clone(rawKey)

	return nil
}

var symmetricConvertibleKeys = []reflect.Type{
	reflect.TypeFor[SymmetricKey](),
}

func octetSeqToRaw(keyif Key, _ any) (any, error) {
	// Fast path: built-in concrete types need no reflection
	switch keyif.(type) {
	case *symmetricKey:
		// already a concrete type, skip extractEmbeddedKey
	default:
		extracted, err := extractEmbeddedKey(keyif, symmetricConvertibleKeys)
		if err != nil {
			return nil, fmt.Errorf(`failed to extract embedded key: %w`, err)
		}
		keyif = extracted
	}

	switch key := keyif.(type) {
	case SymmetricKey:
		var ooctets []byte
		locker, ok := key.(rlocker)
		if ok {
			locker.rlock()
			concrete := key.(*symmetricKey) //nolint:forcetypeassert // rlocker is unexported; only our concrete types implement it
			ooctets = concrete.octets
			locker.runlock()
		} else {
			// External implementation — use self-locking interface getters.
			var ok bool
			if ooctets, ok = key.Octets(); !ok {
				return nil, fmt.Errorf(`jwk.SymmetricKey: missing "k" field`)
			}
		}

		if ooctets == nil {
			return nil, fmt.Errorf(`jwk.SymmetricKey: missing "k" field`)
		}

		octets := make([]byte, len(ooctets))
		copy(octets, ooctets)
		return octets, nil
	default:
		return nil, ContinueError()
	}
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k *symmetricKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	if err := availableHash(hash); err != nil {
		return nil, err
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	octets, err := Export[[]byte](k)
	if err != nil {
		return nil, fmt.Errorf(`failed to export symmetric key: %w`, err)
	}

	h := hash.New()
	fmt.Fprint(h, `{"k":"`)
	fmt.Fprint(h, base64.EncodeToString(octets))
	fmt.Fprint(h, `","kty":"oct"}`)
	return h.Sum(nil), nil
}

func (k *symmetricKey) PublicKey() (Key, error) {
	newKey := newSymmetricKey()

	for _, fk := range k.Keys() {
		v, ok := k.Field(fk)
		if !ok {
			return nil, fmt.Errorf(`failed to get field %q`, fk)
		}
		if err := newKey.Set(fk, v); err != nil {
			return nil, fmt.Errorf(`failed to set field %q: %w`, fk, err)
		}
	}
	return newKey, nil
}

func (k *symmetricKey) Validate() error {
	// Validate only checks that "k" is non-empty. It intentionally does NOT
	// enforce algorithm-specific key lengths even when "alg" is present:
	// RFC 7517/7518 do not require parse-time key-length validation, and "alg"
	// is an informational hint (RFC 7517 §4.4). Exact AES key sizes (for
	// A128/192/256GCM/KW) are enforced at use time (aes.NewCipher rejects a bad
	// length). HMAC minimum key sizes (RFC 7518 §3.2) are NOT enforced here OR
	// at use time — a short non-empty HMAC key is accepted and yields a weak
	// MAC, which is the caller's responsibility. Do NOT add alg-specific
	// length checks below.
	octets, ok := k.Octets()
	if !ok || len(octets) == 0 {
		return NewKeyValidationError(fmt.Errorf(`jwk.SymmetricKey: missing "k" field`))
	}
	return nil
}
