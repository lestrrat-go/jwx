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
	"sync"
)

// X509Decoder decodes a single PEM block into a raw key. Register a
// custom implementation via [RegisterX509Decoder] to extend
// [DecodePEM] (and by extension `jwk.ParseKey` with `jwk.WithPEM(true)`)
// to additional PEM block types such as PQC key formats.
type X509Decoder interface {
	DecodeX509(block *pem.Block) (any, error)
}

// X509DecodeFunc is a function adapter that implements [X509Decoder].
type X509DecodeFunc func(block *pem.Block) (any, error)

// DecodeX509 calls the underlying function.
func (f X509DecodeFunc) DecodeX509(block *pem.Block) (any, error) {
	return f(block)
}

// X509Encoder encodes a raw key into a PEM block type and its DER
// bytes. Register a custom implementation via [RegisterX509Encoder] to
// extend [EncodePEM] (and by extension `jwk.EncodePEM`) to additional
// key families such as PQC keys.
type X509Encoder interface {
	EncodeX509(v any) (blockType string, der []byte, err error)
}

// X509EncodeFunc is a function adapter that implements [X509Encoder].
type X509EncodeFunc func(v any) (blockType string, der []byte, err error)

// EncodeX509 calls the underlying function.
func (f X509EncodeFunc) EncodeX509(v any) (string, []byte, error) {
	return f(v)
}

// muX509 protects both the decoder and encoder registries. Readers
// snapshot the relevant slice under RLock and iterate their own
// immutable copy; writers rebuild the slice so in-flight readers are
// unaffected.
var muX509 sync.RWMutex

var (
	x509Decoders      = map[any]X509Decoder{}
	x509DecoderIdents = []any{}
	x509DecoderList   = []X509Decoder{}
)

var (
	x509Encoders      = map[any]X509Encoder{}
	x509EncoderIdents = []any{}
	x509EncoderList   = []X509Encoder{}
)

type identDefaultX509Decoder struct{}
type identDefaultX509Encoder struct{}

func init() {
	if err := RegisterX509Decoder(identDefaultX509Decoder{}, X509DecodeFunc(func(block *pem.Block) (any, error) {
		return DecodeX509(block)
	})); err != nil {
		panic(fmt.Sprintf("jwkbb: failed to register default X509 decoder: %s", err))
	}
	if err := RegisterX509Encoder(identDefaultX509Encoder{}, X509EncodeFunc(defaultX509Encode)); err != nil {
		panic(fmt.Sprintf("jwkbb: failed to register default X509 encoder: %s", err))
	}
}

// defaultX509Encode handles the stdlib crypto key types supported by
// the main jwk package: RSA, ECDSA, and Ed25519 keys (public and
// private). Anything else must be handled by a registered encoder.
func defaultX509Encode(v any) (string, []byte, error) {
	switch v := v.(type) {
	case *rsa.PrivateKey:
		return RSAPrivateKeyBlockType, x509.MarshalPKCS1PrivateKey(v), nil
	case *ecdsa.PrivateKey:
		marshaled, err := x509.MarshalECPrivateKey(v)
		if err != nil {
			return "", nil, err
		}
		return ECPrivateKeyBlockType, marshaled, nil
	case ed25519.PrivateKey:
		marshaled, err := x509.MarshalPKCS8PrivateKey(v)
		if err != nil {
			return "", nil, err
		}
		return PrivateKeyBlockType, marshaled, nil
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		marshaled, err := x509.MarshalPKIXPublicKey(v)
		if err != nil {
			return "", nil, err
		}
		return PublicKeyBlockType, marshaled, nil
	default:
		return "", nil, fmt.Errorf(`unsupported type %T for ASN.1 DER encoding`, v)
	}
}

// RegisterX509Decoder adds decoder to the registry keyed by ident.
// ident must be comparable and non-nil; decoder must be non-nil. A
// duplicate ident is a no-op (returns nil) to preserve idempotent
// extension-module init() behavior.
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

// RegisterX509Encoder adds encoder to the registry keyed by ident.
// ident must be comparable and non-nil; encoder must be non-nil. A
// duplicate ident is a no-op (returns nil) to preserve idempotent
// extension-module init() behavior.
func RegisterX509Encoder(ident any, encoder X509Encoder) error {
	if ident == nil {
		return errors.New(`jwkbb.RegisterX509Encoder: ident must not be nil`)
	}
	if encoder == nil {
		return errors.New(`jwkbb.RegisterX509Encoder: encoder must not be nil`)
	}

	muX509.Lock()
	defer muX509.Unlock()
	if _, ok := x509Encoders[ident]; ok {
		return nil
	}
	x509Encoders[ident] = encoder
	x509EncoderIdents = append(x509EncoderIdents, ident)
	next := make([]X509Encoder, len(x509EncoderList)+1)
	copy(next, x509EncoderList)
	next[len(x509EncoderList)] = encoder
	x509EncoderList = next
	return nil
}

// UnregisterX509Encoder removes the encoder registered under ident. A
// no-op if no encoder is registered for ident.
func UnregisterX509Encoder(ident any) {
	muX509.Lock()
	defer muX509.Unlock()
	if _, ok := x509Encoders[ident]; !ok {
		return
	}
	delete(x509Encoders, ident)

	nextIdents := make([]any, 0, len(x509EncoderIdents)-1)
	nextList := make([]X509Encoder, 0, len(x509EncoderList)-1)
	for _, id := range x509EncoderIdents {
		if id == ident {
			continue
		}
		nextIdents = append(nextIdents, id)
		nextList = append(nextList, x509Encoders[id])
	}
	x509EncoderIdents = nextIdents
	x509EncoderList = nextList
}

// X509Encoders returns an iterator over every registered [X509Encoder]
// in registration order. The iterator is backed by a snapshot taken at
// call time, so concurrent Register/Unregister activity during
// iteration does not mutate the sequence the caller is walking.
func X509Encoders() iter.Seq[X509Encoder] {
	muX509.RLock()
	snapshot := x509EncoderList
	muX509.RUnlock()
	return func(yield func(X509Encoder) bool) {
		for _, e := range snapshot {
			if !yield(e) {
				return
			}
		}
	}
}

// EncodePEM encodes each key into a PEM block and returns the
// concatenated PEM-encoded bytes in the order given.
//
// Each key is passed through every registered [X509Encoder] in
// registration order; the first encoder that returns without error
// produces the block for that key. An error from any key aborts the
// call; partial output is not returned.
//
// Calling EncodePEM with no keys returns an error.
//
// Keys must be raw Go crypto values (e.g. *rsa.PrivateKey,
// *ecdsa.PublicKey, ed25519.PrivateKey). To encode a [jwk.Key] or a
// [jwk.Set], export to raw via `jwk.Export[any]` / `jwk.ExportAll[any]`
// first and then hand the results here.
func EncodePEM(keys ...any) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New(`jwkbb.EncodePEM: at least one key is required`)
	}

	muX509.RLock()
	snapshot := x509EncoderList
	muX509.RUnlock()

	var out []byte
	for i, v := range keys {
		var errs []error
		encoded := false
		for _, e := range snapshot {
			blockType, der, err := e.EncodeX509(v)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})...)
			encoded = true
			break
		}
		if !encoded {
			return nil, fmt.Errorf(`jwkbb.EncodePEM: key #%d (%T): %w`, i, v, errors.Join(errs...))
		}
	}
	return out, nil
}
