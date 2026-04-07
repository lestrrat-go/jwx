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
	"sync"

	"github.com/lestrrat-go/jwx/v4/internal/ecutil"
)

// # Converting between Raw Keys and `jwk.Key`s
//
// A converter that converts from a raw key to a `jwk.Key` is called a KeyImporter.
// A converter that converts from a `jwk.Key` to a raw key is called a KeyExporter.

var keyImporters = make(map[reflect.Type]KeyImporter)

// KeyKind identifies a key for exporter dispatch. Built-in key types
// use the key type string (e.g. "RSA", "EC", "OKP", "oct"). Keys that
// implement KeyKinder can return a more specific identity
// (e.g. "OKP:Ed448") to select a curve-specific exporter.
type KeyKind string

// KeyKinder is implemented by keys that need exporter dispatch
// beyond just their key type. For example, OKP keys return
// "OKP:<curve>" so that curve-specific exporters can be registered
// by external modules.
//
// Keys that do not implement this interface are dispatched by
// KeyType().String() alone.
type KeyKinder interface {
	KeyKind() KeyKind
}

var keyExporters = make(map[KeyKind][]KeyExporter)

var muKeyImporters sync.RWMutex
var muKeyExporters sync.RWMutex

// RegisterKeyImporter registers a typed import function for converting raw keys of
// type T to jwk.Key. The type is derived from the type parameter, eliminating the
// need to pass a zero value.
//
// When `jwk.Import()` is called, the library will look up the appropriate importer
// for the given raw key type (via `reflect`) and execute it.
func RegisterKeyImporter[T any](fn func(T) (Key, error)) {
	muKeyImporters.Lock()
	defer muKeyImporters.Unlock()
	keyImporters[reflect.TypeFor[T]()] = &keyImportAdapter[T]{fn: fn}
}

// RegisterKeyImporterI registers a KeyImporter interface for the given raw key type.
// This is the interface-based variant for cases where a full KeyImporter implementation
// is needed instead of a simple function.
func RegisterKeyImporterI(from any, conv KeyImporter) {
	muKeyImporters.Lock()
	defer muKeyImporters.Unlock()
	keyImporters[reflect.TypeOf(from)] = conv
}

// RegisterKeyExporter registers a KeyExporter for the given key identity.
// When `jwk.Export()` is called, the library first tries exporters registered
// for the key's specific identity (via [KeyKinder]), then falls back to
// exporters registered for the key type alone.
//
// For most key types, pass `KeyKind(kty.String())` (e.g. `KeyKind("RSA")`).
// For curve-specific exporters, use a compound identity like `KeyKind("OKP:Ed448")`.
func RegisterKeyExporter(ident KeyKind, conv KeyExporter) {
	muKeyExporters.Lock()
	defer muKeyExporters.Unlock()
	convs, ok := keyExporters[ident]
	if !ok {
		convs = []KeyExporter{conv}
	} else {
		convs = append([]KeyExporter{conv}, convs...)
	}
	keyExporters[ident] = convs
}

// KeyImporter is used to convert from a raw key to a `jwk.Key`. mneumonic: from the PoV of the `jwk.Key`,
// we're _importing_ a raw key.
type KeyImporter interface {
	// Import takes the raw key to be converted, and returns a `jwk.Key` or an error if the conversion fails.
	Import(any) (Key, error)
}

// KeyImportFunc is a convenience type to implement KeyImporter as a function.
type KeyImportFunc func(any) (Key, error)

func (f KeyImportFunc) Import(raw any) (Key, error) {
	return f(raw)
}

// keyImportAdapter wraps a typed function into a KeyImporter.
type keyImportAdapter[T any] struct {
	fn func(T) (Key, error)
}

func (a *keyImportAdapter[T]) Import(raw any) (Key, error) {
	v, ok := raw.(T)
	if !ok {
		return nil, fmt.Errorf(`cannot convert key type '%T' to %T`, raw, *new(T))
	}
	return a.fn(v)
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

func init() {
	RegisterKeyImporter(importRSAPrivateKey)
	RegisterKeyImporter(importRSAPrivateKeyPtr)
	RegisterKeyImporter(importRSAPublicKey)
	RegisterKeyImporter(importRSAPublicKeyPtr)
	RegisterKeyImporter(importECDSAPrivateKey)
	RegisterKeyImporter(importECDSAPrivateKeyPtr)
	RegisterKeyImporter(importECDSAPublicKey)
	RegisterKeyImporter(importECDSAPublicKeyPtr)
	RegisterKeyImporter(importEd25519PrivateKey)
	RegisterKeyImporter(importECDHPrivateKey)
	RegisterKeyImporter(importECDHPrivateKeyPtr)
	RegisterKeyImporter(importEd25519PublicKey)
	RegisterKeyImporter(importECDHPublicKey)
	RegisterKeyImporter(importECDHPublicKeyPtr)
	RegisterKeyImporter(importSymmetricKey)
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
		return zero, fmt.Errorf(`jwk.Export: exported %T, requested %T`, v, zero)
	}
	return result, nil
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
		ident := ki.KeyKind()
		if exporters, ok := keyExporters[ident]; ok {
			return exporters
		}
	}
	return keyExporters[KeyKind(key.KeyType().String())]
}
