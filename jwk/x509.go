package jwk

import (
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
)

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
