package jwk

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"sync"

	"github.com/lestrrat-go/jwx/v4/internal/ecutil"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

// # Converting between Raw Keys and `jwk.Key`s
//
// A converter that converts from a raw key to a `jwk.Key` is called a KeyImporter.
// A converter that converts from a `jwk.Key` to a raw key is called a KeyExporter.

// keyImporters stores per-Go-type closures that adapt a typed
// [KeyImporter] (parameterized by the same Go type that keys this map)
// down to a non-generic any-taking dispatch shape. The closure carries
// T and performs the raw.(T) type-assertion before delegating to the
// underlying typed Import method; the assertion is safe because the
// dispatch in [convertRawKey] keys this entry by reflect.TypeOf(raw)
// matching reflect.TypeFor[T]().
var keyImporters = make(map[reflect.Type]func(any) (Key, error))

// builtinImporterTypes is the set of raw key types whose importers
// are owned by the jwk package and cannot be overridden by callers.
// [RegisterKeyImporter] for these types returns an error;
// [UnregisterKeyImporter] for them is a silent no-op. Populated by
// init() via [registerBuiltinImporter].
var builtinImporterTypes = make(map[reflect.Type]struct{})

// KeyKind identifies a key for exporter dispatch. Built-in key types
// use the key type string (e.g. "RSA", "EC", "OKP", "oct"). Keys that
// implement [KeyKinder] can return a more specific identity
// (e.g. "OKP:Ed448") to select a curve-specific exporter.
//
// KeyKind values are compared case-insensitively: both registration
// and lookup normalize to uppercase, so "OKP:Ed448" and "okp:ed448"
// resolve to the same entry.
//
// See [RegisterKeyExporter] for details on how KeyKind values are used
// during export dispatch and how to register exporters for custom key types.
type KeyKind string

// normalize returns the uppercase form of the KeyKind for case-insensitive
// map operations.
func (k KeyKind) normalize() KeyKind {
	return KeyKind(strings.ToUpper(string(k)))
}

// KeyKinder is implemented by keys that need exporter dispatch
// beyond just their key type.
//
// See [KeyKind] and [RegisterKeyExporter] for details on how the
// returned value is used during export.
type KeyKinder interface {
	KeyKind() KeyKind
}

var keyExporters = make(map[KeyKind][]KeyExporter)

var muKeyImporters sync.RWMutex
var muKeyExporters sync.RWMutex

// RegisterKeyImporter registers a [KeyImporter] for the raw key type T.
// The type parameter is normally inferred from the importer's typed
// Import method; pass it explicitly only when inference would fail
// (e.g. when supplying a [KeyImportFunc] without arguments).
//
// When [Import] is called, the library looks up the importer for the
// raw value's runtime type (via reflect) and invokes its Import method
// through a closure that handles the any → T re-typing.
//
// Importer dispatch is single-valued per Go type T: there is exactly
// one importer per reflect.Type. Subsequent registrations for the same
// T return an error ("already registered") and do not replace the
// previous entry. Callers (e.g. tests) that need to swap an existing
// importer must first call [UnregisterKeyImporter] for the same T.
// This intentionally differs from the stacking behavior of
// [RegisterKeyExporter] and [RegisterKeyParser], which dispatch by
// [KeyKind] / untyped JSON and therefore have a meaningful fallback
// chain; importer dispatch is a single-value map keyed by Go type,
// with no equivalent dimension to try next.
//
// The importers for stdlib raw key types — both value and pointer
// forms of rsa.PrivateKey / rsa.PublicKey / ecdsa.PrivateKey /
// ecdsa.PublicKey / ecdh.PrivateKey / ecdh.PublicKey, plus
// ed25519.PrivateKey, ed25519.PublicKey, and []byte — are owned by
// jwk and cannot be overridden. RegisterKeyImporter for any of these
// types returns an error; [UnregisterKeyImporter] for them is a
// silent no-op. Use a wrapper type if you need to apply additional
// validation.
//
// Extension modules calling this from init() must check the returned
// error and panic on failure.
//
// To register from a typed function (the common case for extensions),
// wrap it with [KeyImportFunc]:
//
//	jwk.RegisterKeyImporter(jwk.KeyImportFunc[*mypkg.Key](importMyKey))
func RegisterKeyImporter[T any](ki KeyImporter[T]) error {
	muKeyImporters.Lock()
	defer muKeyImporters.Unlock()
	t := reflect.TypeFor[T]()
	if _, ok := builtinImporterTypes[t]; ok {
		return fmt.Errorf(`jwk.RegisterKeyImporter: %s is a built-in raw key type; built-in importers cannot be overridden`, t)
	}
	if _, exists := keyImporters[t]; exists {
		return fmt.Errorf(`jwk.RegisterKeyImporter: an importer for %s is already registered; call jwk.UnregisterKeyImporter[%s]() first if you need to replace it`, t, t)
	}
	keyImporters[t] = func(raw any) (Key, error) {
		// Safe: dispatch in convertRawKey keys this entry by
		// reflect.TypeOf(raw) matching reflect.TypeFor[T](), so the
		// assertion cannot fail in the lookup path.
		//nolint:forcetypeassert
		return ki.Import(raw.(T))
	}
	return nil
}

// UnregisterKeyImporter removes the importer previously registered
// for type T. Returns true if an importer was removed, false if none
// was registered for T or if T is one of the built-in raw key types
// (see [RegisterKeyImporter] for the list); built-in importers cannot
// be unregistered.
//
// This is primarily useful for tests or for extension modules that
// need to replace a previously installed importer. In steady-state
// code, prefer letting [RegisterKeyImporter] fail with the
// already-registered error; that loud failure catches accidental
// collisions between unrelated extension modules at import time.
func UnregisterKeyImporter[T any]() bool {
	muKeyImporters.Lock()
	defer muKeyImporters.Unlock()
	t := reflect.TypeFor[T]()
	if _, ok := builtinImporterTypes[t]; ok {
		return false
	}
	if _, ok := keyImporters[t]; !ok {
		return false
	}
	delete(keyImporters, t)
	return true
}

// RegisterKeyExporter registers a [KeyExporter] for the given [KeyKind] identity.
//
// When [Export] is called, the library resolves exporters in two steps:
//
//  1. If the key implements [KeyKinder], its KeyKind() value is used to look up
//     exporters registered for that specific identity (e.g. "OKP:Ed448").
//  2. If no exporter is found (or the key does not implement KeyKinder), the
//     library falls back to exporters registered for the key type string alone
//     (i.e. KeyKind(key.KeyType().String()), e.g. "OKP").
//
// This two-level dispatch allows extension modules to register exporters for
// specific curves or algorithms without interfering with built-in exporters.
//
// For most key types, pass KeyKind(kty.String()) as the identity:
//
//	// Handles all RSA keys.
//	jwk.RegisterKeyExporter(jwk.KeyKind("RSA"), myRSAExporter)
//
// For curve- or algorithm-specific exporters, use a compound identity that
// matches the value returned by the key's KeyKind() method:
//
//	// Handles only OKP keys whose curve is Ed448.
//	// Built-in OKP keys return "OKP:<curve>" from KeyKind().
//	jwk.RegisterKeyExporter(jwk.KeyKind("OKP:Ed448"), myEd448Exporter)
//
// The identity is normalized to uppercase before storage, so registration
// is case-insensitive: KeyKind("OKP:Ed448") and KeyKind("okp:ed448") refer
// to the same entry.
//
// Multiple exporters can be registered for the same identity. They are tried
// in reverse registration order (last registered is tried first). An exporter
// can return [ContinueError] to decline a key and let the next exporter try.
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterKeyExporter(ident KeyKind, conv KeyExporter) error {
	muKeyExporters.Lock()
	defer muKeyExporters.Unlock()
	norm := ident.normalize()
	convs, ok := keyExporters[norm]
	if !ok {
		convs = []KeyExporter{conv}
	} else {
		convs = append([]KeyExporter{conv}, convs...)
	}
	keyExporters[norm] = convs
	return nil
}

// KeyImporter converts a raw key of Go type T into a [jwk.Key]. The
// type parameter T is the raw-key type the importer handles. From the
// point of view of the `jwk.Key`, we're _importing_ a raw key.
//
// Implementations are registered with [RegisterKeyImporter]; T flows
// through to [reflect.TypeFor] at registration time to key the import
// dispatch table.
type KeyImporter[T any] interface {
	// Import takes the raw key to be converted, and returns a
	// [jwk.Key] or an error if the conversion fails.
	Import(raw T) (Key, error)
}

// KeyImportFunc is the typed-function adapter that satisfies
// [KeyImporter] for type T. The Import method just calls f directly —
// no internal type assertion is needed because [KeyImporter]'s Import
// is itself typed.
//
// This is the canonical way to register a typed import function:
//
//	jwk.RegisterKeyImporter(jwk.KeyImportFunc[*mypkg.Key](importMyKey))
//
// For an importer with non-trivial state, implement [KeyImporter] on
// your own type and pass an instance of it directly.
type KeyImportFunc[T any] func(T) (Key, error)

func (f KeyImportFunc[T]) Import(raw T) (Key, error) {
	return f(raw)
}

// KeyExporter is used to convert from a `jwk.Key` to a raw key. From the PoV of the `jwk.Key`,
// we're _exporting_ it to a raw key.
type KeyExporter interface {
	// Export takes the `jwk.Key` to be converted, and an optional hint
	// indicating the desired output type. The hint may be nil, in which
	// case the exporter should return the default/natural type for the key.
	//
	// Export should return jwk.ContinueError if the key is not compatible
	// with this exporter, so that the next exporter can be tried.
	Export(Key, any) (any, error)
}

// KeyExportFunc is a convenience type to implement KeyExporter as a function.
type KeyExportFunc func(Key, any) (any, error)

func (f KeyExportFunc) Export(key Key, hint any) (any, error) {
	return f(key, hint)
}

// Pre-computed normalized KeyKind values for built-in key types.
// These avoid strings.ToUpper allocations in the export dispatch hot path.
var (
	normalizedRSA KeyKind
	normalizedEC  KeyKind
	normalizedOKP KeyKind
	normalizedOCT KeyKind
)

func init() {
	normalizedRSA = KeyKind(jwa.RSA().String()).normalize()
	normalizedEC = KeyKind(jwa.EC().String()).normalize()
	normalizedOKP = KeyKind(jwa.OKP().String()).normalize()
	normalizedOCT = KeyKind(jwa.OctetSeq().String()).normalize()

	registerBuiltinKeyImporter(importRSAPrivateKey)
	registerBuiltinKeyImporter(importRSAPrivateKeyPtr)
	registerBuiltinKeyImporter(importRSAPublicKey)
	registerBuiltinKeyImporter(importRSAPublicKeyPtr)
	registerBuiltinKeyImporter(importECDSAPrivateKey)
	registerBuiltinKeyImporter(importECDSAPrivateKeyPtr)
	registerBuiltinKeyImporter(importECDSAPublicKey)
	registerBuiltinKeyImporter(importECDSAPublicKeyPtr)
	registerBuiltinKeyImporter(importEd25519PrivateKey)
	registerBuiltinKeyImporter(importECDHPrivateKey)
	registerBuiltinKeyImporter(importECDHPrivateKeyPtr)
	registerBuiltinKeyImporter(importEd25519PublicKey)
	registerBuiltinKeyImporter(importECDHPublicKey)
	registerBuiltinKeyImporter(importECDHPublicKeyPtr)
	registerBuiltinKeyImporter(importSymmetricKey)
}

// registerBuiltinKeyImporter installs an importer that the public
// [RegisterKeyImporter] / [UnregisterKeyImporter] APIs are not allowed
// to touch. Intended for jwk's own init() — runs single-threaded
// before any goroutine could observe partially-populated state, so
// the muKeyImporters lock is not taken.
func registerBuiltinKeyImporter[T any](fn func(T) (Key, error)) {
	t := reflect.TypeFor[T]()
	builtinImporterTypes[t] = struct{}{}
	keyImporters[t] = func(raw any) (Key, error) {
		// Safe: dispatch keys this entry by reflect.TypeOf(raw)
		// matching reflect.TypeFor[T](); the assertion cannot fail
		// when the closure is invoked from convertRawKey.
		//nolint:forcetypeassert
		return fn(raw.(T))
	}
}

// panicOnRegistrationError converts a non-nil error returned by a Register*
// call during jwk's own init() into a panic. Registration cannot actually
// fail today, but the API reserves the error return for future validation
// and this helper keeps builtin bootstrap honest if that ever changes.
func panicOnRegistrationError(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwk: failed to register builtin: %s", err))
	}
}

// normalizedKeyKindForType returns the pre-computed normalized KeyKind
// for built-in key types, avoiding strings.ToUpper allocation.
func normalizedKeyKindForType(kty jwa.KeyType) KeyKind {
	switch kty {
	case jwa.RSA():
		return normalizedRSA
	case jwa.EC():
		return normalizedEC
	case jwa.OKP():
		return normalizedOKP
	case jwa.OctetSeq():
		return normalizedOCT
	case jwa.AKP():
		return normalizedAKP
	default:
		return KeyKind(kty.String()).normalize()
	}
}

// Typed importer functions. Each accepts the concrete type directly,
// eliminating the type-switch boilerplate from v3.

func importRSAPrivateKey(raw rsa.PrivateKey) (Key, error) {
	return importRSAPrivateKeyPtr(&raw)
}

func importRSAPrivateKeyPtr(raw *rsa.PrivateKey) (Key, error) {
	k := newRSAPrivateKey()
	if err := k.Import(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func importRSAPublicKey(raw rsa.PublicKey) (Key, error) {
	return importRSAPublicKeyPtr(&raw)
}

func importRSAPublicKeyPtr(raw *rsa.PublicKey) (Key, error) {
	k := newRSAPublicKey()
	if err := k.Import(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func importECDSAPrivateKey(raw ecdsa.PrivateKey) (Key, error) {
	return importECDSAPrivateKeyPtr(&raw)
}

func importECDSAPrivateKeyPtr(raw *ecdsa.PrivateKey) (Key, error) {
	k := newECDSAPrivateKey()
	if err := k.Import(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func importECDSAPublicKey(raw ecdsa.PublicKey) (Key, error) {
	return importECDSAPublicKeyPtr(&raw)
}

func importECDSAPublicKeyPtr(raw *ecdsa.PublicKey) (Key, error) {
	k := newECDSAPublicKey()
	if err := k.Import(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func importEd25519PrivateKey(raw ed25519.PrivateKey) (Key, error) {
	k := newOKPPrivateKey()
	if err := k.Import(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func importEd25519PublicKey(raw ed25519.PublicKey) (Key, error) {
	k := newOKPPublicKey()
	if err := k.Import(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func importECDHPrivateKey(raw ecdh.PrivateKey) (Key, error) {
	return importECDHPrivateKeyPtr(&raw)
}

func importECDHPrivateKeyPtr(raw *ecdh.PrivateKey) (Key, error) {
	switch raw.Curve() {
	case ecdh.X25519():
		k := newOKPPrivateKey()
		if err := k.Import(raw); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
		}
		return k, nil
	case ecdh.P256():
		return ecdhPrivateKeyToECJWK(raw, elliptic.P256())
	case ecdh.P384():
		return ecdhPrivateKeyToECJWK(raw, elliptic.P384())
	case ecdh.P521():
		return ecdhPrivateKeyToECJWK(raw, elliptic.P521())
	default:
		return nil, fmt.Errorf(`unsupported curve %s`, raw.Curve())
	}
}

func ecdhPrivateKeyToECJWK(raw *ecdh.PrivateKey, crv elliptic.Curve) (Key, error) {
	pub := raw.PublicKey()
	rawpub := pub.Bytes()

	size := ecutil.CalculateKeySize(crv)
	var x, y, d big.Int
	x.SetBytes(rawpub[1 : 1+size])
	y.SetBytes(rawpub[1+size:])
	d.SetBytes(raw.Bytes())

	var ecdsaPriv ecdsa.PrivateKey
	ecdsaPriv.Curve = crv
	ecdsaPriv.D = &d
	ecdsaPriv.X = &x
	ecdsaPriv.Y = &y
	return importECDSAPrivateKeyPtr(&ecdsaPriv)
}

func importECDHPublicKey(raw ecdh.PublicKey) (Key, error) {
	return importECDHPublicKeyPtr(&raw)
}

func importECDHPublicKeyPtr(raw *ecdh.PublicKey) (Key, error) {
	switch raw.Curve() {
	case ecdh.X25519():
		k := newOKPPublicKey()
		if err := k.Import(raw); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
		}
		return k, nil
	case ecdh.P256():
		return ecdhPublicKeyToECJWK(raw, elliptic.P256())
	case ecdh.P384():
		return ecdhPublicKeyToECJWK(raw, elliptic.P384())
	case ecdh.P521():
		return ecdhPublicKeyToECJWK(raw, elliptic.P521())
	default:
		return nil, fmt.Errorf(`unsupported curve %s`, raw.Curve())
	}
}

func ecdhPublicKeyToECJWK(raw *ecdh.PublicKey, crv elliptic.Curve) (Key, error) {
	rawbytes := raw.Bytes()
	size := ecutil.CalculateKeySize(crv)
	var x, y big.Int

	x.SetBytes(rawbytes[1 : 1+size])
	y.SetBytes(rawbytes[1+size:])
	var ecdsaPub ecdsa.PublicKey
	ecdsaPub.Curve = crv
	ecdsaPub.X = &x
	ecdsaPub.Y = &y
	return importECDSAPublicKeyPtr(&ecdsaPub)
}

func importSymmetricKey(raw []byte) (Key, error) {
	k := newSymmetricKey()
	if err := k.Import(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

// Export converts a jwk.Key into a raw key of type T.
//
// The type parameter T specifies the desired output type. For most keys,
// the type is unambiguous (e.g. RSA keys always export as *rsa.PrivateKey).
// For EC keys, the type parameter selects between *ecdsa.PrivateKey and
// *ecdh.PrivateKey.
//
// Use [any] as the type parameter to let the exporter choose the default type:
//
//	raw, err := jwk.Export[any](key)
//
// Examples:
//
//	privkey, err := jwk.Export[*rsa.PrivateKey](key)
//	ecdhkey, err := jwk.Export[*ecdh.PrivateKey](key)
//	octets, err := jwk.Export[[]byte](key)
func Export[T any](key Key) (T, error) {
	var zero T
	v, err := doExport(key, any(*new(T)))
	if err != nil {
		return zero, err
	}
	result, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf(`jwk.Export: %w`, KeyTypeMismatchError{
			Got:  reflect.TypeOf(v),
			Want: reflect.TypeFor[T](),
		})
	}
	return result, nil
}

// ExportAll exports every key in the given [Set] to type T, preserving
// insertion order. It is the plural counterpart to [Export] and fails
// fast on the first key whose raw representation cannot be asserted to
// T.
//
// For a heterogeneous [Set] whose members don't share a concrete raw
// type, use `T = any`:
//
//	raws, err := jwk.ExportAll[any](set)
//
// Each element's dynamic type then matches the source key's raw form
// (e.g. *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey).
//
// Use a concrete T when every member shares a representation:
//
//	privkeys, err := jwk.ExportAll[*rsa.PrivateKey](set)
//
// An empty [Set] returns an empty slice and a nil error.
func ExportAll[T any](set Set) ([]T, error) {
	if set == nil {
		return nil, fmt.Errorf(`jwk.ExportAll: set must not be nil`)
	}
	out := make([]T, 0, set.Len())
	i := 0
	for _, k := range set.All() {
		v, err := Export[T](k)
		if err != nil {
			return nil, fmt.Errorf(`jwk.ExportAll: key #%d: %w`, i, err)
		}
		out = append(out, v)
		i++
	}
	return out, nil
}

func doExport(key Key, hint any) (any, error) {
	muKeyExporters.RLock()
	exporters := findExporters(key)
	muKeyExporters.RUnlock()

	if len(exporters) == 0 {
		return nil, fmt.Errorf(`jwk.Export: no exporters registered for key type '%T'`, key)
	}
	for _, conv := range exporters {
		v, err := conv.Export(key, hint)
		if err != nil {
			if errors.Is(err, ContinueError()) {
				continue
			}
			return nil, fmt.Errorf(`jwk.Export: failed to export jwk.Key to raw format: %w`, err)
		}
		return v, nil
	}
	return nil, fmt.Errorf(`jwk.Export: no suitable exporter found for key type '%T'`, key)
}

// findExporters returns exporters for the key, trying the specific
// KeyKind first, then falling back to the key type. Caller must
// hold muKeyExporters.RLock.
func findExporters(key Key) []KeyExporter {
	if ki, ok := key.(KeyKinder); ok {
		ident := ki.KeyKind().normalize()
		if exporters, ok := keyExporters[ident]; ok {
			return exporters
		}
	}
	return keyExporters[normalizedKeyKindForType(key.KeyType())]
}
