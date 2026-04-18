package jwkbb

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"sync"
)

// X509Decoder parses a PEM block's DER payload into a value of type T.
// Register a custom implementation via [RegisterX509Decoder] to teach
// [DecodeX509] (and by extension `jwk.ParseKey` with `jwk.WithX509(true)`)
// about additional PEM block types such as PQC key formats.
//
// The type parameter T is the decoder's concrete return type. It gives
// registration sites a compile-time guarantee that the function body
// returns what it claims to return; [DecodeX509] internally erases T to
// `any` for heterogeneous dispatch.
type X509Decoder[T any] interface {
	DecodeX509(block *pem.Block) (T, error)
}

// X509DecodeFunc is a function adapter that implements [X509Decoder].
type X509DecodeFunc[T any] func(block *pem.Block) (T, error)

// DecodeX509 calls the underlying function.
func (f X509DecodeFunc[T]) DecodeX509(block *pem.Block) (T, error) {
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

// Registry-internal erased shapes. Each Register call boxes the typed
// decoder/encoder into one of these adapters, so the heterogeneous
// map can hold entries for arbitrary T without chain-iteration
// ceremony.

type x509Decoder interface {
	decode(block *pem.Block) (any, error)
}

type x509DecoderAdapter[T any] struct {
	dec X509Decoder[T]
}

func (a *x509DecoderAdapter[T]) decode(block *pem.Block) (any, error) {
	return a.dec.DecodeX509(block)
}

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

// muX509 protects both registries. Readers take an RLock, look up
// their entry, and release before calling user code, so a misbehaving
// decoder/encoder cannot block writers.
var muX509 sync.RWMutex

var (
	x509Decoders = map[string]x509Decoder{}
	x509Encoders = map[reflect.Type]x509Encoder{}
)

func init() {
	// Default decoders — one per stdlib PEM block type. Splitting the
	// historical block-type switch into discrete registrations is what
	// lets extension modules add new PEM formats (ML-DSA, ML-KEM, …)
	// just by calling RegisterX509Decoder[T] with their block type.
	panicIfRegisterDefaultDecoderFailed(RegisterX509Decoder[*rsa.PrivateKey](RSAPrivateKeyBlockType, X509DecodeFunc[*rsa.PrivateKey](decodeRSAPrivateKey)))
	panicIfRegisterDefaultDecoderFailed(RegisterX509Decoder[*rsa.PublicKey](RSAPublicKeyBlockType, X509DecodeFunc[*rsa.PublicKey](decodeRSAPublicKey)))
	panicIfRegisterDefaultDecoderFailed(RegisterX509Decoder[*ecdsa.PrivateKey](ECPrivateKeyBlockType, X509DecodeFunc[*ecdsa.PrivateKey](decodeECPrivateKey)))
	panicIfRegisterDefaultDecoderFailed(RegisterX509Decoder[any](PrivateKeyBlockType, X509DecodeFunc[any](decodePKCS8PrivateKey)))
	panicIfRegisterDefaultDecoderFailed(RegisterX509Decoder[any](PublicKeyBlockType, X509DecodeFunc[any](decodePKIXPublicKey)))
	panicIfRegisterDefaultDecoderFailed(RegisterX509Decoder[any](CertificateBlockType, X509DecodeFunc[any](decodeCertificate)))

	// Default encoders — same story on the encode side, keyed by
	// runtime Go type instead of block type.
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[*rsa.PrivateKey](X509EncodeFunc[*rsa.PrivateKey](rsaPrivateKeyEncoder)))
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[*ecdsa.PrivateKey](X509EncodeFunc[*ecdsa.PrivateKey](ecdsaPrivateKeyEncoder)))
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[ed25519.PrivateKey](X509EncodeFunc[ed25519.PrivateKey](ed25519PrivateKeyEncoder)))
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[*rsa.PublicKey](X509EncodeFunc[*rsa.PublicKey](rsaPublicKeyEncoder)))
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[*ecdsa.PublicKey](X509EncodeFunc[*ecdsa.PublicKey](ecdsaPublicKeyEncoder)))
	panicIfRegisterDefaultEncoderFailed(RegisterX509Encoder[ed25519.PublicKey](X509EncodeFunc[ed25519.PublicKey](ed25519PublicKeyEncoder)))
}

func panicIfRegisterDefaultDecoderFailed(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwkbb: failed to register default X509 decoder: %s", err))
	}
}

func panicIfRegisterDefaultEncoderFailed(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwkbb: failed to register default X509 encoder: %s", err))
	}
}

// Default decoder implementations. Each handles exactly one PEM block
// type and returns the concrete Go value stdlib produces for that
// format.

func decodeRSAPrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func decodeRSAPublicKey(block *pem.Block) (*rsa.PublicKey, error) {
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func decodeECPrivateKey(block *pem.Block) (*ecdsa.PrivateKey, error) {
	return x509.ParseECPrivateKey(block.Bytes)
}

// PKCS#8 wraps any of RSA/ECDSA/Ed25519 private keys; stdlib sniffs
// the OID internally, so the return type here is legitimately `any`.
func decodePKCS8PrivateKey(block *pem.Block) (any, error) {
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

// PKIX/SPKI similarly wraps any public key type; return shape is `any`.
func decodePKIXPublicKey(block *pem.Block) (any, error) {
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// decodeCertificate extracts the embedded public key. Chain validation,
// expiration, CN/SAN, EKU, etc. are intentionally not performed here —
// they are an application-level concern.
func decodeCertificate(block *pem.Block) (any, error) {
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(`failed to parse certificate: %w`, err)
	}
	return cert.PublicKey, nil
}

// Default encoder implementations — one per stdlib crypto type.

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

// RegisterX509Decoder installs decoder as the handler for PEM blocks
// of the given blockType. [DecodeX509] dispatches by block.Type, so
// exactly one decoder owns a given string. A later Register for the
// same blockType overwrites the previous registration — the library
// uses this to install its stdlib defaults at init(); callers that
// want to scope an override should call [UnregisterX509Decoder] at
// teardown to restore the default (or re-register it).
//
// blockType must be non-empty; decoder must be non-nil.
func RegisterX509Decoder[T any](blockType string, decoder X509Decoder[T]) error {
	if blockType == "" {
		return errors.New(`jwkbb.RegisterX509Decoder: blockType must not be empty`)
	}
	if decoder == nil {
		return errors.New(`jwkbb.RegisterX509Decoder: decoder must not be nil`)
	}
	muX509.Lock()
	defer muX509.Unlock()
	x509Decoders[blockType] = &x509DecoderAdapter[T]{dec: decoder}
	return nil
}

// UnregisterX509Decoder removes the decoder registered for blockType.
// A no-op if no decoder is registered for blockType.
func UnregisterX509Decoder(blockType string) {
	muX509.Lock()
	defer muX509.Unlock()
	delete(x509Decoders, blockType)
}

// DecodeX509 dispatches block to the decoder registered for
// block.Type and returns its raw key (the type produced by the
// decoder, erased to `any`). Returns an error if no decoder is
// registered for block.Type.
func DecodeX509(block *pem.Block) (any, error) {
	muX509.RLock()
	dec, ok := x509Decoders[block.Type]
	muX509.RUnlock()
	if !ok {
		return nil, fmt.Errorf(`jwkbb.DecodeX509: no decoder registered for block type %q`, block.Type)
	}
	return dec.decode(block)
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
