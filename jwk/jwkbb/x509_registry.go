package jwkbb

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"iter"
	"reflect"
	"sync"
)

// X509Decoder decodes a single PEM block into a raw key. Register a
// custom implementation via [RegisterX509Decoder] to extend
// `jwk.ParseKey` with `jwk.WithX509(true)` to additional PEM block
// types such as PQC key formats.
type X509Decoder interface {
	DecodeX509(block *pem.Block) (any, error)
}

// X509DecodeFunc is a function adapter that implements [X509Decoder].
type X509DecodeFunc func(block *pem.Block) (any, error)

// DecodeX509 calls the underlying function.
func (f X509DecodeFunc) DecodeX509(block *pem.Block) (any, error) {
	return f(block)
}

// X509Encoder encodes a value of type T into a PEM block type and its
// DER bytes. Register a custom implementation via [RegisterX509Encoder]
// to extend [EncodePEM] to additional key families such as PQC keys.
//
// The type parameter is the key under which the encoder is registered:
// [EncodePEM] dispatches by the runtime type of each input value, so a
// caller that registers `X509Encoder[*mypkg.Key]` will receive
// `*mypkg.Key` values and nothing else.
type X509Encoder[T any] interface {
	EncodeX509(v T) (blockType string, der []byte, err error)
}

// X509EncodeFunc is a function adapter that implements [X509Encoder].
type X509EncodeFunc[T any] func(v T) (blockType string, der []byte, err error)

// EncodeX509 calls the underlying function.
func (f X509EncodeFunc[T]) EncodeX509(v T) (string, []byte, error) {
	return f(v)
}

// x509Encoder is the registry-internal erased shape. Each registration
// stores a [x509EncoderAdapter] that unboxes the `any` back to the
// parameterized T and forwards to the user-supplied encoder.
type x509Encoder interface {
	encode(v any) (blockType string, der []byte, err error)
}

type x509EncoderAdapter[T any] struct {
	enc X509Encoder[T]
}

func (a *x509EncoderAdapter[T]) encode(v any) (string, []byte, error) {
	typed, ok := v.(T)
	if !ok {
		return "", nil, fmt.Errorf(`jwkbb: encoder registered for %T cannot encode %T`, *new(T), v)
	}
	return a.enc.EncodeX509(typed)
}

// muX509 protects both registries. Decoder readers take an RLock,
// capture the current slice header, and release before iterating —
// writers replace the variable with a freshly allocated slice so
// in-flight readers keep walking their immutable copy. Encoder reads
// are direct map lookups under RLock with no user code called while
// the lock is held.
var muX509 sync.RWMutex

var (
	x509Decoders      = map[any]X509Decoder{}
	x509DecoderIdents = []any{}
	x509DecoderList   = []X509Decoder{}
)

var x509Encoders = map[reflect.Type]x509Encoder{}

type identDefaultX509Decoder struct{}

func init() {
	if err := RegisterX509Decoder(identDefaultX509Decoder{}, X509DecodeFunc(func(block *pem.Block) (any, error) {
		return DecodeX509(block)
	})); err != nil {
		panic(fmt.Sprintf("jwkbb: failed to register default X509 decoder: %s", err))
	}

	// Default encoders, one per stdlib crypto type. Splitting the
	// old type-switch across discrete registrations is what lets
	// extension modules slot in a new key family (ML-DSA, ML-KEM, …)
	// just by calling RegisterX509Encoder[T] — no central dispatch to
	// edit.
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[*rsa.PrivateKey](X509EncodeFunc[*rsa.PrivateKey](rsaPrivateKeyEncoder)))
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[*ecdsa.PrivateKey](X509EncodeFunc[*ecdsa.PrivateKey](ecdsaPrivateKeyEncoder)))
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[ed25519.PrivateKey](X509EncodeFunc[ed25519.PrivateKey](ed25519PrivateKeyEncoder)))
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[*rsa.PublicKey](X509EncodeFunc[*rsa.PublicKey](rsaPublicKeyEncoder)))
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[*ecdsa.PublicKey](X509EncodeFunc[*ecdsa.PublicKey](ecdsaPublicKeyEncoder)))
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[ed25519.PublicKey](X509EncodeFunc[ed25519.PublicKey](ed25519PublicKeyEncoder)))
}

func panicIfRegisterDefaultEncoderFailed(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwkbb: failed to register default X509 encoder: %s", err))
	}
}

func rsaPrivateKeyEncoder(v *rsa.PrivateKey) (string, []byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(v)
	if err != nil {
		return "", nil, err
	}
	return PrivateKeyBlockType, der, nil
}

func ecdsaPrivateKeyEncoder(v *ecdsa.PrivateKey) (string, []byte, error) {
	der, err := x509.MarshalECPrivateKey(v)
	if err != nil {
		return "", nil, err
	}
	return ECPrivateKeyBlockType, der, nil
}

func ed25519PrivateKeyEncoder(v ed25519.PrivateKey) (string, []byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(v)
	if err != nil {
		return "", nil, err
	}
	return PrivateKeyBlockType, der, nil
}

func rsaPublicKeyEncoder(v *rsa.PublicKey) (string, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(v)
	if err != nil {
		return "", nil, err
	}
	return PublicKeyBlockType, der, nil
}

func ecdsaPublicKeyEncoder(v *ecdsa.PublicKey) (string, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(v)
	if err != nil {
		return "", nil, err
	}
	return PublicKeyBlockType, der, nil
}

func ed25519PublicKeyEncoder(v ed25519.PublicKey) (string, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(v)
	if err != nil {
		return "", nil, err
	}
	return PublicKeyBlockType, der, nil
}

// RegisterX509Decoder adds decoder to the registry keyed by ident.
// ident must be comparable and non-nil; decoder must be non-nil. A
// duplicate ident is a no-op (returns nil) to preserve idempotent
// extension-module init() behavior.
//
// Decoders are tried in registration order. The built-in stdlib
// decoder is registered first during package init, so custom decoders
// effectively extend the set of recognized PEM block types rather
// than override stdlib handling — a custom decoder for a standard
// block type (e.g. `RSA PRIVATE KEY`) will never be reached because
// the default decoder claims it first. This is deliberate: it keeps
// stdlib parsing stable regardless of which extension modules are
// loaded.
func RegisterX509Decoder(ident any, decoder X509Decoder) error {
	if ident == nil {
		return errors.New(`jwkbb.RegisterX509Decoder: ident must not be nil`)
	}
	if decoder == nil {
		return errors.New(`jwkbb.RegisterX509Decoder: decoder must not be nil`)
	}

	muX509.Lock()
	defer muX509.Unlock()
	if _, ok := x509Decoders[ident]; ok {
		return nil
	}
	x509Decoders[ident] = decoder
	x509DecoderIdents = append(x509DecoderIdents, ident)
	next := make([]X509Decoder, len(x509DecoderList)+1)
	copy(next, x509DecoderList)
	next[len(x509DecoderList)] = decoder
	x509DecoderList = next
	return nil
}

// UnregisterX509Decoder removes the decoder registered under ident. A
// no-op if no decoder is registered for ident.
func UnregisterX509Decoder(ident any) {
	muX509.Lock()
	defer muX509.Unlock()
	if _, ok := x509Decoders[ident]; !ok {
		return
	}
	delete(x509Decoders, ident)

	nextIdents := make([]any, 0, len(x509DecoderIdents)-1)
	nextList := make([]X509Decoder, 0, len(x509DecoderList)-1)
	for _, id := range x509DecoderIdents {
		if id == ident {
			continue
		}
		nextIdents = append(nextIdents, id)
		nextList = append(nextList, x509Decoders[id])
	}
	x509DecoderIdents = nextIdents
	x509DecoderList = nextList
}

// X509Decoders returns an iterator over every registered [X509Decoder]
// in registration order. The iterator is backed by a snapshot taken at
// call time, so concurrent Register/Unregister activity during
// iteration does not mutate the sequence the caller is walking.
func X509Decoders() iter.Seq[X509Decoder] {
	muX509.RLock()
	snapshot := x509DecoderList
	muX509.RUnlock()
	return func(yield func(X509Decoder) bool) {
		for _, d := range snapshot {
			if !yield(d) {
				return
			}
		}
	}
}

// RegisterX509Encoder installs encoder as the handler for values of
// type T. [EncodePEM] dispatches by the runtime type of each input, so
// exactly one encoder owns a given Go type. A later Register for the
// same T overwrites the previous registration — the library uses this
// to install its stdlib defaults in init(); callers that want to
// override a default should call [UnregisterX509Encoder] first (or
// accept the overwrite) and are responsible for restoring the default
// at shutdown if the override was meant to be scoped.
//
// encoder must be non-nil. The error return is reserved for future
// validation; today it only surfaces a nil-encoder programming error.
func RegisterX509Encoder[T any](encoder X509Encoder[T]) error {
	if encoder == nil {
		return errors.New(`jwkbb.RegisterX509Encoder: encoder must not be nil`)
	}
	muX509.Lock()
	defer muX509.Unlock()
	x509Encoders[reflect.TypeFor[T]()] = &x509EncoderAdapter[T]{enc: encoder}
	return nil
}

// UnregisterX509Encoder removes the encoder registered for type T. A
// no-op if no encoder is registered for T.
func UnregisterX509Encoder[T any]() {
	muX509.Lock()
	defer muX509.Unlock()
	delete(x509Encoders, reflect.TypeFor[T]())
}

// EncodePEM encodes each key into a PEM block and returns the
// concatenated PEM-encoded bytes in the order given.
//
// Each key is dispatched by its runtime Go type to the encoder
// registered via [RegisterX509Encoder]. A key with no registered
// encoder aborts the call; partial output is not returned.
//
// Calling EncodePEM with no keys returns an error.
//
// Keys must be raw Go crypto values (e.g. *rsa.PrivateKey,
// *ecdsa.PublicKey, ed25519.PrivateKey). To encode a [jwk.Key] or a
// [jwk.Set], export to raw via `jwk.Export[any]` / `jwk.ExportAll[any]`
// first and then hand the results here.
//
// Named types are looked up by exact identity: a value declared as a
// raw `[]byte` will not match an encoder registered for
// `ed25519.PublicKey` even though the underlying types are equal.
// Callers that round-trip through `jwk.Export[any]` get the named
// type back and do not need to worry about this.
func EncodePEM(keys ...any) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New(`jwkbb.EncodePEM: at least one key is required`)
	}

	var out []byte
	for i, v := range keys {
		t := reflect.TypeOf(v)
		muX509.RLock()
		enc, ok := x509Encoders[t]
		muX509.RUnlock()
		if !ok {
			return nil, fmt.Errorf(`jwkbb.EncodePEM: key #%d (%T): no encoder registered; EncodePEM requires raw Go crypto keys (e.g. *rsa.PrivateKey, *ecdsa.PublicKey, ed25519.PrivateKey). Convert a jwk.Key via jwk.Export[any] or a jwk.Set via jwk.ExportAll[any] first, or register a custom encoder with jwkbb.RegisterX509Encoder`, i, v)
		}
		blockType, der, err := enc.encode(v)
		if err != nil {
			return nil, fmt.Errorf(`jwkbb.EncodePEM: key #%d (%T): %w`, i, v, err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})...)
	}
	return out, nil
}
