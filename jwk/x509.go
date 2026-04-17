package jwk

import (
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
)

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

// decodeX509 decodes a single PEM block from src. It returns the
// decoded value, the remaining bytes after the consumed block, and any
// error. Callers iterate by calling this repeatedly with the returned
// rest until empty.
//
// decodeX509 iterates every [jwkbb.X509Decoder] registered via
// [jwkbb.RegisterX509Decoder] in registration order; the first
// decoder that succeeds wins.
func decodeX509(src []byte) (any, []byte, error) {
	block, rest := pem.Decode(src)
	if block == nil {
		return nil, rest, fmt.Errorf(`failed to decode PEM data`)
	}

	var errs []error
	for d := range jwkbb.X509Decoders() {
		ret, err := d.DecodeX509(block)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return ret, rest, nil
	}
	return nil, rest, fmt.Errorf(`failed to decode X509 data using any of the decoders: %w`, errors.Join(errs...))
}
