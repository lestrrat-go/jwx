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
	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/jwx/v3/internal/tokens"
)

type Base64Encoder interface {
	// AppendEncode appends the Base64URL encoded version of the input to the output.
	AppendEncode(dst, src []byte) []byte
}

// Signer is an interface that defines the method for signing payloads.
type Signer[K any] interface {
	Sign(payload []byte, key K) ([]byte, error)
}

func sign[K any](payload, hdr []byte, signer Signer[K], encoder Base64Encoder, encodePayload bool, key K) ([]byte, error) {
	buf := pool.ByteSlice().GetCapacity(len(payload) + len(hdr) + 1)

	buf = encoder.AppendEncode(buf, hdr)
	buf = append(buf, tokens.Period)
	if encodePayload {
		buf = encoder.AppendEncode(buf, payload)
	} else {
		buf = append(buf, payload...)
	}

	defer pool.ByteSlice().Put(buf)
	return signer.Sign(buf, key)
}

type Verifier[K any] interface {
	Verify(buf []byte, signature []byte, key K) error
}

func verify[K any](payload, hdr, signature []byte, verifier Verifier[K], encoder Base64Encoder, encodePayload bool, key K) error {
	buf := pool.ByteSlice().GetCapacity(len(payload) + len(hdr) + 1)

	buf = encoder.AppendEncode(buf, hdr)
	buf = append(buf, tokens.Period)
	if encodePayload {
		buf = encoder.AppendEncode(buf, payload)
	} else {
		buf = append(buf, payload...)
	}

	defer pool.ByteSlice().Put(buf)
	return verifier.Verify(buf, signature, key)
}
