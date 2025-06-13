// Package jwsbb provides the building blocks (hence the name "bb") for JWS operations.
// It should be thought of as a low-level API, almost akin to internal packages
// that should not be used directly by users of the jwx package. However, these exist
// to provide a more efficient way to perform JWS operations without the overhead of
// the higher-level jws package to power-users who know what they are doing.
//
// This package is currently considered EXPERIMENTAL, and the API may change
// without notice. It is not recommended to use this package unless you are
// fully aware of the implications of using it.
//
// All bb packages in jwx follow the same design principles:
// 1. Does minimal checking of input parameters (for performance); callers need to ensure that the parameters are valid.
// 2. All exported functions are stringly typed (i.e. they do not take interface{} parameters unless they absolutely have to).
// 3. Does not rely on other public jwx packages (they are standalone, except for internal packages).
package jwsbb

import (
	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/jwx/v3/internal/tokens"
)

// Signer is an interface that defines the method for signing payloads.
type Signer[K any] interface {
	Sign(key K, payload []byte) ([]byte, error)
}

type Verifier[K any] interface {
	Verify(key K, buf []byte, signature []byte) error
}

func Verify[K any](key K, payload, hdr, signature []byte, verifier Verifier[K], encoder base64.Encoder, encodePayload bool) error {
	buf := pool.ByteSlice().GetCapacity(len(payload) + len(hdr) + 1)

	buf = encoder.AppendEncode(buf, hdr)
	buf = append(buf, tokens.Period)
	if encodePayload {
		buf = encoder.AppendEncode(buf, payload)
	} else {
		buf = append(buf, payload...)
	}

	defer pool.ByteSlice().Put(buf)
	return verifier.Verify(key, buf, signature)
}
