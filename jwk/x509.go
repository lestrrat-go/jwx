package jwk

import (
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
)

// PEMDecoder is an interface to describe an object that can decode
// a key from PEM encoded ASN.1 DER format.
//
// A PEMDecoder can be specified as an option to `jwk.Parse()` or `jwk.ParseKey()`
// along with the `jwk.WithPEM()` option.
type PEMDecoder interface {
	Decode([]byte) (any, []byte, error)
}

// PEMDecodeFunc is a function adapter that implements PEMDecoder,
// mirroring PEMEncodeFunc for symmetry.
type PEMDecodeFunc func([]byte) (any, []byte, error)

func (f PEMDecodeFunc) Decode(src []byte) (any, []byte, error) {
	return f(src)
}

// PEMEncoder is an interface to describe an object that can encode
// a key into PEM encoded ASN.1 DER format.
//
// `jwk.Key` instances do not implement a way to encode themselves into
// PEM format. Normally you can just use `jwk.EncodePEM()` to do this, but
// this interface allows you to generalize the encoding process by
// abstracting the `jwk.EncodePEM()` function using `jwk.PEMEncodeFunc`
// along with alternate implementations, should you need them.
type PEMEncoder interface {
	Encode(any) (string, []byte, error)
}

type PEMEncodeFunc func(any) (string, []byte, error)

func (f PEMEncodeFunc) Encode(v any) (string, []byte, error) {
	return f(v)
}

// EncodePEM encodes the key into PEM encoded ASN.1 DER format.
// The key can be a jwk.Key or a raw key instance. Custom key types
// can be handled by registering an [jwkbb.X509Encoder] via
// [jwkbb.RegisterX509Encoder].
func EncodePEM(v any) ([]byte, error) {
	if key, ok := v.(Key); ok {
		raw, err := Export[any](key)
		if err != nil {
			return nil, fmt.Errorf(`failed to get raw key out of %T: %w`, key, err)
		}
		v = raw
	}

	var errs []error
	for e := range jwkbb.X509Encoders() {
		blockType, der, err := e.EncodeX509(v)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		block := &pem.Block{Type: blockType, Bytes: der}
		return pem.EncodeToMemory(block), nil
	}
	return nil, fmt.Errorf(`failed to encode %T using any of the encoders: %w`, v, errors.Join(errs...))
}

// NewPEMDecoder returns a PEMDecoder that decodes keys in PEM encoded ASN.1 DER format.
// You can use it as argument to `jwk.WithPEMDecoder()` option.
//
// The use of this function is planned to be deprecated. The plan is to replace the
// `jwk.WithPEMDecoder()` option with globally available custom X509 decoders which
// can be registered via [jwkbb.RegisterX509Decoder].
func NewPEMDecoder() PEMDecoder {
	return pemDecoder{}
}

type pemDecoder struct{}

// Decode decodes a key in PEM encoded ASN.1 DER format.
// and returns a raw key.
func (pemDecoder) Decode(src []byte) (any, []byte, error) {
	block, rest := pem.Decode(src)
	if block == nil {
		return nil, rest, fmt.Errorf(`failed to decode PEM data`)
	}
	ret, err := jwkbb.DecodeX509(block)
	if err != nil {
		return nil, rest, err
	}
	return ret, rest, nil
}

// decodeX509 decodes a PEM encoded ASN.1 DER format and returns the raw
// key. It iterates every [jwkbb.X509Decoder] registered via
// [jwkbb.RegisterX509Decoder] in registration order; the first decoder
// that succeeds wins.
func decodeX509(src []byte) (any, error) {
	block, _ := pem.Decode(src)
	if block == nil {
		return nil, fmt.Errorf(`failed to decode PEM data`)
	}

	var errs []error
	for d := range jwkbb.X509Decoders() {
		ret, err := d.DecodeX509(block)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return ret, nil
	}
	return nil, fmt.Errorf(`failed to decode X509 data using any of the decoders: %w`, errors.Join(errs...))
}

func decodeX509WithPEMDEcoder(src []byte, decoder PEMDecoder) (any, error) {
	ret, _, err := decoder.Decode(src)
	if err != nil {
		return nil, fmt.Errorf(`failed to decode PEM data: %w`, err)
	}

	return ret, nil
}
