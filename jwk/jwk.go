//go:generate ../scripts/jwxcodegen.sh generate-jwk -objects=objects.yml

package jwk

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/option/v3"
)

var fieldRegistry = json.NewRegistry()

func bigIntToBytes(n *big.Int) ([]byte, error) {
	if n == nil {
		return nil, fmt.Errorf(`invalid *big.Int value`)
	}
	return n.Bytes(), nil
}

// maxKeys bounds the number of keys accepted by Parse() from a single
// input. It applies to both the JSON `keys` array and the PEM block
// stream: each entry triggers a probe + unmarshal + validation, and
// callers cannot predict that amplification from the raw input size
// alone. Tunable via WithMaxKeys / Settings(WithMaxKeys(...)).
var maxKeys atomic.Int64

// rejectDuplicateKID makes Parse/UnmarshalJSON fail when the JWKS
// carries two or more keys with the same non-empty "kid". Default is
// false (RFC 7517 allows duplicates; LookupKeyID returns the first).
// Tunable via WithRejectDuplicateKID / Settings(WithRejectDuplicateKID(...)).
var rejectDuplicateKID atomic.Bool

func init() {
	maxKeys.Store(1000)

	if err := RegisterProbeField[string]("Kty", "kty"); err != nil {
		panic(fmt.Errorf("failed to register mandatory probe for 'kty' field: %w", err))
	}
	if err := RegisterProbeField[json.RawMessage]("D", "d"); err != nil {
		panic(fmt.Errorf("failed to register mandatory probe for 'd' field: %w", err))
	}
}

// Import creates a validated jwk.Key from the given key
// (RSA/ECDSA/symmetric keys).
//
// The constructor auto-detects the type of key to be instantiated
// based on the input type:
//
//   - "crypto/rsa".PrivateKey and "crypto/rsa".PublicKey creates an RSA based key
//   - "crypto/ecdsa".PrivateKey and "crypto/ecdsa".PublicKey creates an EC based key
//   - "crypto/ed25519".PrivateKey and "crypto/ed25519".PublicKey creates an OKP based key
//   - "crypto/ecdh".PrivateKey and "crypto/ecdh".PublicKey creates an OKP based key
//   - []byte creates a symmetric key
//
// The type parameter T specifies the expected key type. Use [Key] when you
// do not need a specific subtype:
//
//	key, err := jwk.Import[jwk.Key](rawKey)
//
// Use a concrete key type to obtain a typed result directly:
//
//	rsaKey, err := jwk.Import[jwk.RSAPrivateKey](rawRSAKey)
//
// Import validates the populated JWK before returning it. Malformed raw
// keys fail at import time instead of being returned for later validation.
func Import[T Key](raw any) (T, error) {
	var zero T
	key, err := doImport(raw)
	if err != nil {
		return zero, err
	}
	result, ok := key.(T)
	if !ok {
		return zero, importerr(`%w`, KeyTypeMismatchError{
			Got:  reflect.TypeOf(key),
			Want: reflect.TypeFor[T](),
		})
	}
	return result, nil
}

func validateImportedKey(key Key) error {
	if key == nil {
		return nil
	}
	if err := key.Validate(); err != nil {
		return importerr(`key validation failed: %w`, err)
	}
	return nil
}

var errNotBuiltinKey = errors.New(`not a builtin key`)

func importBuiltinKey(raw any) (Key, error) {
	switch v := raw.(type) {
	case *rsa.PrivateKey:
		return importRSAPrivateKeyPtr(v)
	case *rsa.PublicKey:
		return importRSAPublicKeyPtr(v)
	case rsa.PrivateKey:
		return importRSAPrivateKey(v)
	case rsa.PublicKey:
		return importRSAPublicKey(v)
	case *ecdsa.PrivateKey:
		return importECDSAPrivateKeyPtr(v)
	case *ecdsa.PublicKey:
		return importECDSAPublicKeyPtr(v)
	case ecdsa.PrivateKey:
		return importECDSAPrivateKey(v)
	case ecdsa.PublicKey:
		return importECDSAPublicKey(v)
	case ed25519.PrivateKey:
		return importEd25519PrivateKey(v)
	case ed25519.PublicKey:
		return importEd25519PublicKey(v)
	case *ecdh.PrivateKey:
		return importECDHPrivateKeyPtr(v)
	case *ecdh.PublicKey:
		return importECDHPublicKeyPtr(v)
	case ecdh.PrivateKey:
		return importECDHPrivateKey(v)
	case ecdh.PublicKey:
		return importECDHPublicKey(v)
	case []byte:
		return importSymmetricKey(v)
	default:
		return nil, errNotBuiltinKey
	}
}

func convertRawKey(raw any) (Key, error) {
	if raw == nil {
		return nil, fmt.Errorf(`a non-nil key is required`)
	}

	key, err := importBuiltinKey(raw)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, errNotBuiltinKey) {
		return nil, err
	}

	muKeyImporters.RLock()
	conv, ok := keyImporters[reflect.TypeOf(raw)]
	muKeyImporters.RUnlock()
	if !ok {
		return nil, fmt.Errorf(`failed to convert %T to jwk.Key: no converters were able to convert`, raw)
	}

	return conv.Import(raw)
}

func doImport(raw any) (Key, error) {
	key, err := convertRawKey(raw)
	if err != nil {
		return nil, importerr(`%w`, err)
	}
	if err := validateImportedKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

func validateReturnedKey(key Key) error {
	if key == nil {
		return nil
	}
	if err := key.Validate(); err != nil {
		return err
	}
	return nil
}

// PublicSetOf returns a new jwk.Set consisting of
// public keys of the keys contained in the set.
//
// This is useful when you are generating a set of private keys, and
// you want to generate the corresponding public versions for the
// users to verify with.
//
// By default, if the input set contains a symmetric (oct) key, this
// function returns an error: a symmetric key has no public form, and
// its "public" representation would be the secret itself. Publishing
// such a set (e.g. as `/.well-known/jwks.json`) would leak secret
// material. Callers who explicitly want the legacy pass-through
// behavior can opt in with `jwk.WithAllowSymmetric(true)`.
//
// Be aware that for asymmetric private keys, all fields will be
// copied onto the new public key. It is the caller's responsibility
// to remove any fields, if necessary.
func PublicSetOf(v Set, options ...PublicSetOption) (Set, error) {
	var allowSymmetric bool
	for _, opt := range options {
		switch opt.Ident() {
		case identAllowSymmetric{}:
			allowSymmetric = option.MustGet[bool](opt)
		}
	}

	newSet := NewSet()

	n := v.Len()
	for i := range n {
		k, ok := v.Key(i)
		if !ok {
			return nil, fmt.Errorf(`key not found`)
		}
		if k.KeyType() == jwa.OctetSeq() && !allowSymmetric {
			kid, _ := k.KeyID()
			return nil, fmt.Errorf(`jwk.PublicSetOf: input set contains a symmetric key (kid=%q, index=%d); symmetric keys have no public form and would leak secret material if published. Remove symmetric keys from the set before calling PublicSetOf, or pass jwk.WithAllowSymmetric(true) to opt into legacy pass-through behavior`, kid, i)
		}
		pubKey, err := PublicKeyOf(k)
		if err != nil {
			return nil, fmt.Errorf(`failed to get public key of %T: %w`, k, err)
		}
		if err := newSet.AddKey(pubKey); err != nil {
			return nil, fmt.Errorf(`failed to add key to public key set: %w`, err)
		}
	}

	return newSet, nil
}

// PublicKeyOf returns the corresponding public version of the jwk.Key.
// If `v` is a SymmetricKey, then the same value is returned.
// If `v` is already a public key, the key itself is returned.
//
// If `v` is a private key type that has a `PublicKey()` method, be aware
// that all fields will be copied onto the new public key. It is the caller's
// responsibility to remove any fields, if necessary
//
// If `v` is a raw key, the key is first converted to a `jwk.Key`.
//
// Symmetric (oct) key pass-through: a symmetric key has no distinct public
// counterpart, so `PublicKeyOf` returns it unchanged. This is intentional,
// but it means the returned value is NOT safe to publish: doing so would
// leak the shared secret. Callers who intend to publish the result (for
// example as part of a `/.well-known/jwks.json` document) must filter out
// symmetric keys themselves, or use `PublicSetOf`, which rejects symmetric
// keys by default and requires an explicit `jwk.WithAllowSymmetric(true)`
// opt-in for the legacy pass-through behavior.
func PublicKeyOf(v any) (Key, error) {
	// This should catch all jwk.Key instances
	if pk, ok := v.(PublicKeyer); ok {
		return pk.PublicKey()
	}

	jk, err := doImport(v)
	if err != nil {
		return nil, fmt.Errorf(`jwk.PublicKeyOf: failed to convert key into JWK: %w`, err)
	}

	return jk.PublicKey()
}

// PublicRawKeyOf returns the corresponding public key of the given
// value `v` (e.g. given *rsa.PrivateKey, *rsa.PublicKey is returned)
// If `v` is already a public key, the key itself is returned.
//
// The returned value will always be a pointer to the public key,
// except when a []byte (e.g. symmetric key, ed25519 key) is passed to `v`.
// In this case, the same []byte value is returned.
//
// This function must go through converting the object once to a jwk.Key,
// then back to a raw key, so it's not exactly efficient.
func PublicRawKeyOf(v any) (any, error) {
	pk, ok := v.(PublicKeyer)
	if !ok {
		k, err := doImport(v)
		if err != nil {
			return nil, fmt.Errorf(`jwk.PublicRawKeyOf: failed to convert key to jwk.Key: %w`, err)
		}

		pk, ok = k.(PublicKeyer)
		if !ok {
			return nil, fmt.Errorf(`jwk.PublicRawKeyOf: failed to convert key to jwk.PublicKeyer: %w`, err)
		}
	}

	pubk, err := pk.PublicKey()
	if err != nil {
		return nil, fmt.Errorf(`jwk.PublicRawKeyOf: failed to obtain public key from %T: %w`, v, err)
	}

	raw, err := Export[any](pubk)
	if err != nil {
		return nil, fmt.Errorf(`jwk.PublicRawKeyOf: failed to obtain raw key from %T: %w`, pubk, err)
	}
	return raw, nil
}

// ParseRawKey is a combination of ParseKey and Raw. It parses a single JWK key,
// and assigns the "raw" key to the given parameter. The key must either be
// a pointer to an empty interface, or a pointer to the actual raw key type
// such as *rsa.PrivateKey, *ecdsa.PublicKey, *[]byte, etc.
func ParseRawKey(data []byte, rawkey any) error {
	key, err := doParseKey(data)
	if err != nil {
		return fmt.Errorf(`failed to parse key: %w`, err)
	}

	raw, err := Export[any](key)
	if err != nil {
		return fmt.Errorf(`failed to export raw key: %w`, err)
	}

	rv := reflect.ValueOf(rawkey)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf(`rawkey must be a non-nil pointer`)
	}
	elem := rv.Elem()
	rawVal := reflect.ValueOf(raw)
	if !rawVal.Type().AssignableTo(elem.Type()) {
		return fmt.Errorf(`cannot assign %T to %s`, raw, elem.Type())
	}
	elem.Set(rawVal)

	return nil
}

type setDecodeCtx struct {
	json.DecodeCtx

	ignoreParseError bool
}

func (ctx *setDecodeCtx) IgnoreParseError() bool {
	return ctx.ignoreParseError
}

// ParseKey parses a single key JWK and returns it as a [Key]. Unlike
// [Parse] this method reports failure if the input is a JWK set. Only
// use this function when you know that the data is a single JWK.
//
// Given a WithX509(true) option, this function assumes that the given input
// is a PEM-framed X.509-encoded key.
//
// Note that a successful parsing of any type of key does NOT necessarily
// guarantee a valid key. For example, no checks against expiration dates
// are performed for certificate expiration, no checks against missing
// parameters are performed, etc.
//
// Use [ParseKeyAs] when a concrete key subtype (e.g. [RSAPrivateKey],
// [ECDSAPublicKey]) is required.
func ParseKey(data []byte, options ...ParseOption) (Key, error) {
	return doParseKey(data, options...)
}

// ParseKeyAs behaves like [ParseKey] but asserts the parsed key to the
// concrete type T. On a type mismatch it returns a [KeyTypeMismatchError]
// carrying the parsed and requested types; the underlying error chain also
// satisfies [errors.Is] with a sentinel [ParseError].
//
//	ecKey, err := jwk.ParseKeyAs[jwk.ECDSAPublicKey](data)
func ParseKeyAs[T Key](data []byte, options ...ParseOption) (T, error) {
	var zero T
	key, err := doParseKey(data, options...)
	if err != nil {
		return zero, err
	}
	result, ok := key.(T)
	if !ok {
		return zero, parseerr(`%w`, KeyTypeMismatchError{
			Got:  reflect.TypeOf(key),
			Want: reflect.TypeFor[T](),
		})
	}
	return result, nil
}

func doParseKey(data []byte, options ...ParseOption) (Key, error) {
	var parseX509 bool
	var localReg *json.Registry
	for _, opt := range options {
		switch opt.Ident() {
		case identX509{}:
			parseX509 = option.MustGet[bool](opt)
		case identLocalRegistry{}:
			localReg = option.MustGet[*json.Registry](opt)
		case identTypedField{}:
			pair := option.MustGet[typedFieldPair](opt)
			if localReg == nil {
				localReg = json.NewRegistry()
			}
			localReg.Register(pair.Name, pair.Value)
		case identIgnoreParseError{}:
			return nil, fmt.Errorf(`jwk.WithIgnoreParseError() cannot be used for ParseKey()`)
		}
	}

	if parseX509 {
		raw, _, err := decodeX509(data)
		if err != nil {
			return nil, fmt.Errorf(`failed to decode PEM/X.509 encoded key: %w`, err)
		}
		key, err := convertRawKey(raw)
		if err != nil {
			return nil, fmt.Errorf(`jwk.Parse: failed to create jwk.Key from %T: %w`, raw, err)
		}
		if err := validateReturnedKey(key); err != nil {
			return nil, fmt.Errorf(`jwk.Parse: %w`, err)
		}
		return key, nil
	}

	probe, err := keyProbe.Probe(data)
	if err != nil {
		return nil, fmt.Errorf(`jwk.Parse: failed to probe data: %w`, err)
	}

	unmarshaler := keyUnmarshaler{localReg: localReg}

	muKeyParser.RLock()
	parsers := make([]KeyParser, len(keyParsers))
	copy(parsers, keyParsers)
	muKeyParser.RUnlock()

	for i := len(parsers) - 1; i >= 0; i-- {
		parser := parsers[i]
		key, err := parser.ParseKey(probe, &unmarshaler, data)
		if err == nil {
			if err := validateReturnedKey(key); err != nil {
				return nil, fmt.Errorf(`jwk.Parse: %w`, err)
			}
			return key, nil
		}

		if errors.Is(err, ContinueError()) {
			continue
		}

		return nil, err
	}
	return nil, fmt.Errorf(`jwk.Parse: no parser was able to parse the key`)
}

// Parse parses JWK from the incoming []byte.
//
// For JWK sets, this is a convenience function. You could just as well
// call `json.Unmarshal` against an empty set created by `jwk.NewSet()`
// to parse a JSON buffer into a `jwk.Set`.
//
// This function exists because many times the user does not know before hand
// if a JWK(s) resource at a remote location contains a single JWK key or
// a JWK set, and `jwk.Parse()` can handle either case, returning a JWK Set
// even if the data only contains a single JWK key
//
// If you are looking for more information on how JWKs are parsed, or if
// you know for sure that you have a single key, please see the documentation
// for `jwk.ParseKey()`.
func Parse(src []byte, options ...ParseOption) (Set, error) {
	var parseX509 bool
	var localReg *json.Registry
	var ignoreParseError bool
	maxK := int(maxKeys.Load())
	rejectDupKid := rejectDuplicateKID.Load()
	for _, opt := range options {
		switch opt.Ident() {
		case identX509{}:
			parseX509 = option.MustGet[bool](opt)
		case identIgnoreParseError{}:
			ignoreParseError = option.MustGet[bool](opt)
		case identTypedField{}:
			pair := option.MustGet[typedFieldPair](opt)
			if localReg == nil {
				localReg = json.NewRegistry()
			}
			localReg.Register(pair.Name, pair.Value)
		case identMaxKeys{}:
			v := option.MustGet[int](opt)
			if v <= 0 {
				return nil, parseerr(`WithMaxKeys must be greater than zero, got %d`, v)
			}
			maxK = v
		case identRejectDuplicateKID{}:
			rejectDupKid = option.MustGet[bool](opt)
		}
	}

	s := NewSet()

	if parseX509 {
		src = bytes.TrimSpace(src)
		var keyCount int
		for len(src) > 0 {
			raw, rest, err := decodeX509(src)
			if err != nil {
				return nil, parseerr(`failed to parse PEM encoded key: %w`, err)
			}
			key, err := convertRawKey(raw)
			if err != nil {
				return nil, parseerr(`failed to create jwk.Key from %T: %w`, raw, err)
			}
			if err := validateReturnedKey(key); err != nil {
				return nil, parseerr(`%w`, err)
			}
			if err := s.AddKey(key); err != nil {
				return nil, parseerr(`failed to add jwk.Key to set: %w`, err)
			}
			keyCount++
			if keyCount > maxK {
				return nil, parseerr(`too many keys in PEM input: max %d`, maxK)
			}
			src = bytes.TrimSpace(rest)
		}
		if rejectDupKid {
			if kid, dup := firstDuplicateKID(s); dup {
				return nil, parseerr(`duplicate "kid" %q in PEM input`, kid)
			}
		}
		return s, nil
	}

	if localReg != nil || ignoreParseError {
		dcKs, ok := s.(KeyWithDecodeCtx)
		if !ok {
			return nil, parseerr(`typed field was requested, but the key set (%T) does not support DecodeCtx`, s)
		}
		dc := &setDecodeCtx{
			DecodeCtx:        json.NewDecodeCtx(localReg),
			ignoreParseError: ignoreParseError,
		}
		dcKs.SetDecodeCtx(dc)
		defer func() { dcKs.SetDecodeCtx(nil) }()
	}

	// Propagate the resolved cap to Set.UnmarshalJSON. A scratch field
	// rather than a ParseOption thread-through keeps json.Unmarshal happy.
	if setter, ok := s.(interface{ setMaxKeys(int) }); ok {
		setter.setMaxKeys(maxK)
		defer setter.setMaxKeys(0)
	}
	if setter, ok := s.(interface{ setRejectDuplicateKID(bool) }); ok && rejectDupKid {
		setter.setRejectDuplicateKID(true)
		defer setter.setRejectDuplicateKID(false)
	}

	if err := json.Unmarshal(src, s); err != nil {
		return nil, parseerr(`failed to unmarshal JWK set: %w`, err)
	}

	return s, nil
}

// firstDuplicateKID returns the first non-empty kid that appears more
// than once in s, or ("", false) if every non-empty kid is unique.
func firstDuplicateKID(s Set) (string, bool) {
	seen := make(map[string]struct{}, s.Len())
	for i := range s.Len() {
		key, _ := s.Key(i)
		kid, ok := key.KeyID()
		if !ok || kid == "" {
			continue
		}
		if _, dup := seen[kid]; dup {
			return kid, true
		}
		seen[kid] = struct{}{}
	}
	return "", false
}

// ParseReader parses a JWK set from the incoming byte buffer.
func ParseReader(src io.Reader, options ...ParseOption) (Set, error) {
	// meh, there's no way to tell if a stream has "ended" a single
	// JWKs except when we encounter an EOF, so just... ReadAll
	buf, err := io.ReadAll(src)
	if err != nil {
		return nil, rparseerr(`failed to read from io.Reader: %w`, err)
	}

	set, err := Parse(buf, options...)
	if err != nil {
		return nil, rparseerr(`failed to parse reader: %w`, err)
	}
	return set, nil
}

// ParseString parses a JWK set from the incoming string.
func ParseString(s string, options ...ParseOption) (Set, error) {
	set, err := Parse([]byte(s), options...)
	if err != nil {
		return nil, sparseerr(`failed to parse string: %w`, err)
	}
	return set, nil
}

// AssignKeyID is a convenience function to automatically assign the "kid"
// section of the key, if it already doesn't have one. It uses Key.Thumbprint
// method with crypto.SHA256 as the default hashing algorithm.
//
// By default, if the key already carries a `kid`, `AssignKeyID` leaves it
// alone and returns nil. Pass `jwk.WithForceAssign(true)` to force
// recomputation (for example, when upgrading to a stronger thumbprint hash
// via `jwk.WithThumbprintHash`).
func AssignKeyID(key Key, options ...AssignKeyIDOption) error {
	hash := crypto.SHA256
	var force bool
	for _, opt := range options {
		switch opt.Ident() {
		case identThumbprintHash{}:
			hash = option.MustGet[crypto.Hash](opt)
		case identForceAssign{}:
			force = option.MustGet[bool](opt)
		}
	}

	if !force && key.Has(KeyIDKey) {
		return nil
	}

	h, err := key.Thumbprint(hash)
	if err != nil {
		return fmt.Errorf(`failed to generate thumbprint: %w`, err)
	}

	if err := key.Set(KeyIDKey, base64.EncodeToString(h)); err != nil {
		return fmt.Errorf(`failed to set "kid": %w`, err)
	}

	return nil
}

// CustomDecoder is a generic interface for custom field decoders.
type CustomDecoder[T any] = json.CustomDecoder[T]

// CustomDecodeFunc is a function-based implementation of CustomDecoder[T].
type CustomDecodeFunc[T any] = json.CustomDecodeFunc[T]

// RegisterCustomField registers a private field to be decoded as type T
// using json.Unmarshal. This option has a global effect.
//
// For example, suppose you have a custom field `x-birthday`, which
// you want to represent as a string formatted in RFC3339 in JSON,
// but want it back as `time.Time`.
//
//	jwk.RegisterCustomField[time.Time](`x-birthday`)
//
// For more fine-tuned control over the decoding process,
// use RegisterCustomDecoder instead.
//
// Please note that use of custom fields can be problematic if you
// are using a library that does not implement MarshalJSON/UnmarshalJSON
// and you try to roundtrip from an object to JSON, and then back to an object.
// To avoid this, it's always better to use a custom type
// that wraps your desired type and implement MarshalJSON and UnmarshalJSON.
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterCustomField[T any](name string) error {
	json.RegisterTyped[T](fieldRegistry, name)
	return nil
}

// RegisterCustomDecoder registers a private field with a custom decoder
// function. This option has a global effect.
//
// For example, below shows how to register a decoder that can parse
// RFC1123 format string:
//
//	jwk.RegisterCustomDecoder(`x-birthday`, jwk.CustomDecodeFunc[time.Time](func(data []byte) (time.Time, error) {
//	  var s string
//	  if err := json.Unmarshal(data, &s); err != nil {
//	    return time.Time{}, err
//	  }
//	  return time.Parse(time.RFC1123, s)
//	}))
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterCustomDecoder[T any](name string, dec CustomDecodeFunc[T]) error {
	json.RegisterCustomDecoder[T](fieldRegistry, name, dec)
	return nil
}

// UnregisterCustomField removes the registration for a custom field.
//
// The error return is reserved for future validation (for example,
// refusing to unregister a built-in field) and is always nil today.
// Callers — especially extension modules scripting Register/Unregister
// cycles from init() — should check the returned value and propagate
// on failure to stay forward-compatible, matching the convention on
// [RegisterCustomField] / [RegisterCustomDecoder].
func UnregisterCustomField(name string) error {
	fieldRegistry.Unregister(name)
	return nil
}

// Equal compares two keys and returns true if they are equal. The comparison
// is solely done against the thumbprints of k1 and k2. It is possible for keys
// that have, for example, different key IDs, key usage, etc, to be considered equal.
func Equal(k1, k2 Key) bool {
	h := crypto.SHA256
	tp1, err := k1.Thumbprint(h)
	if err != nil {
		return false // can't report error
	}
	tp2, err := k2.Thumbprint(h)
	if err != nil {
		return false // can't report error
	}

	return bytes.Equal(tp1, tp2)
}

// IsPrivateKey returns true if the supplied key is a private key of an
// asymmetric key pair. The argument `k` must implement the `AsymmetricKey`
// interface.
//
// An error is returned if the supplied key is not an `AsymmetricKey`.
func IsPrivateKey(k Key) (bool, error) {
	asymmetric, ok := k.(AsymmetricKey)
	if ok {
		return asymmetric.IsPrivate(), nil
	}
	return false, fmt.Errorf("jwk.IsPrivateKey: %T is not an asymmetric key", k)
}

type keyValidationError struct {
	err error
}

func (e *keyValidationError) Error() string {
	return fmt.Sprintf(`key validation failed: %s`, e.err)
}

func (e *keyValidationError) Unwrap() error {
	return e.err
}

func (e *keyValidationError) Is(target error) bool {
	_, ok := target.(*keyValidationError)
	return ok
}

// NewKeyValidationError wraps the given error with an error that denotes
// `key.Validate()` has failed. This error type should ONLY be used as
// return value from the `Validate()` method.
func NewKeyValidationError(err error) error {
	return &keyValidationError{err: err}
}

func IsKeyValidationError(err error) bool {
	var kve keyValidationError
	return errors.Is(err, &kve)
}

// Settings is used to configure global behavior of the jwk package.
//
// Returns a non-nil error and applies no changes if any option fails
// validation (for example, a non-positive [WithMaxKeys]). Extension
// modules calling this from init() must check the return value and
// panic on failure.
func Settings(options ...GlobalOption) error {
	var newMaxKeys int64
	for _, opt := range options {
		switch opt.Ident() {
		case identMaxKeys{}:
			v := option.MustGet[int](opt)
			if v <= 0 {
				return fmt.Errorf(`jwk.Settings: WithMaxKeys must be greater than zero, got %d`, v)
			}
			newMaxKeys = int64(v)
		}
	}

	for _, opt := range options {
		switch opt.Ident() {
		case identMinRSAModulusBits{}:
			rsaMinModulusBits.Store(int64(option.MustGet[int](opt)))
		case identMinRSAPublicExponent{}:
			setMinRSAPublicExponent(option.MustGet[int](opt))
		case identStrictKeyUsage{}:
			strictKeyUsage.Store(option.MustGet[bool](opt))
		case identRejectDuplicateKID{}:
			rejectDuplicateKID.Store(option.MustGet[bool](opt))
		}
	}

	if newMaxKeys > 0 {
		maxKeys.Store(newMaxKeys)
	}
	return nil
}

// These are used when validating keys.
type keyWithD interface {
	D() ([]byte, bool)
}

var _ keyWithD = &okpPrivateKey{}

func extractEmbeddedKey(keyif Key, concretTypes []reflect.Type) (Key, error) {
	rv := reflect.ValueOf(keyif)

	// If the value can be converted to one of the concrete types, then we're done
	if slices.ContainsFunc(concretTypes, func(t reflect.Type) bool {
		return rv.Type().ConvertibleTo(t)
	}) {
		return keyif, nil
	}

	// When a struct implements the Key interface via embedding, you unfortunately
	// cannot use a type switch to determine the concrete type, because
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil, fmt.Errorf(`invalid key value (0): %w`, ContinueError())
		}
		rv = rv.Elem()
	}

	if rv.Kind() != reflect.Struct {
		return nil, fmt.Errorf(`invalid key value type %T (1): %w`, keyif, ContinueError())
	}
	if rv.NumField() == 0 {
		return nil, fmt.Errorf(`invalid key value type %T (2): %w`, keyif, ContinueError())
	}
	// Iterate through the fields of the struct to find the first field that
	// implements the Key interface
	rt := rv.Type()
	for i := range rv.NumField() {
		field := rv.Field(i)
		ft := rt.Field(i)
		if !ft.Anonymous {
			// We can only salvage this object if the object implements jwk.Key
			// via embedding, so we skip fields that are not anonymous
			continue
		}

		if field.CanInterface() {
			if k, ok := field.Interface().(Key); ok {
				return extractEmbeddedKey(k, concretTypes)
			}
		}
	}

	return nil, fmt.Errorf(`invalid key value type %T (3): %w`, keyif, ContinueError())
}
