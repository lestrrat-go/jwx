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
	"bytes"
	"errors"
	"io"

	"github.com/lestrrat-go/jwx/v3/internal/jwxio"
	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/jwx/v3/internal/tokens"
)

type Base64Encoder interface {
	// AppendEncode appends the Base64URL encoded version of the input to the output.
	AppendEncode(dst, src []byte) []byte
}

// Signer is an interface that defines the method for signing payloads.
type Signer[K any] interface {
	Sign(key K, payload []byte) ([]byte, error)
}

type SignerFunc[K any] func(key K, payload []byte) ([]byte, error)

func (fn SignerFunc[K]) Sign(key K, payload []byte) ([]byte, error) {
	return fn(key, payload)
}

// Sign takes the basic compnents of a JWS (payload, header, and key), creates a
// combined buffer to be used to generate a signature, and then calls the
// `signer` to generate the signature.
//
// It's a low-level function that does not perform any validation of the input parameters,
// so callers need to ensure that the parameters are valid before calling this function.
//
// Users who want to provide a custom signing implementation should implement the `Signer` interface.
// and plug it into this function.
func Sign[K any](key K, payload, hdr []byte, signer Signer[K], encoder Base64Encoder, encodePayload bool) ([]byte, error) {
	buf := pool.ByteSlice().GetCapacity(len(payload) + len(hdr) + 1)

	buf = encoder.AppendEncode(buf, hdr)
	buf = append(buf, tokens.Period)
	if encodePayload {
		buf = encoder.AppendEncode(buf, payload)
	} else {
		buf = append(buf, payload...)
	}

	defer pool.ByteSlice().Put(buf)
	return signer.Sign(key, buf)
}

type Verifier[K any] interface {
	Verify(key K, buf []byte, signature []byte) error
}

func Verify[K any](key K, payload, hdr, signature []byte, verifier Verifier[K], encoder Base64Encoder, encodePayload bool) error {
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

// Join combines the header, payload, and signature into a single byte slice,
// using the specified Base64Encoder to encode the components.
func Join(buf, hdr, payload, signature []byte, encoder Base64Encoder) []byte {
	l := len(hdr) + len(payload) + len(signature) + 2
	if cap(buf) < l {
		buf = make([]byte, 0, l)
	}
	buf = buf[:0]
	buf = encoder.AppendEncode(buf, hdr)
	buf = append(buf, tokens.Period)
	buf = encoder.AppendEncode(buf, payload)
	buf = append(buf, tokens.Period)
	buf = encoder.AppendEncode(buf, signature)

	return buf
}

var compactDelim = []byte{tokens.Period}

var errInvalidNumberOfSegments = errors.New(`jwsbb: invalid number of segments`)

func InvalidNumberOfSegmentsError() error {
	return errInvalidNumberOfSegments
}

// SplitCompact splits the JWS into its components: header, payload, and signature.
func SplitCompact(src []byte) (protected, payload, signature []byte, err error) {
	var s []byte
	var ok bool

	protected, s, ok = bytes.Cut(src, compactDelim)
	if !ok { // no period found
		return nil, nil, nil, InvalidNumberOfSegmentsError()
	}
	payload, s, ok = bytes.Cut(s, compactDelim)
	if !ok { // only one period found
		return nil, nil, nil, InvalidNumberOfSegmentsError()
	}
	signature, _, ok = bytes.Cut(s, compactDelim)
	if ok { // three periods found
		return nil, nil, nil, InvalidNumberOfSegmentsError()
	}
	return protected, payload, signature, nil
}

// SplieCompactString splits the JWS into its components: header, payload, and signature.
func SplitCompactString(src string) (protected, payload, signature []byte, err error) {
	return SplitCompact([]byte(src))
}

func SplitCompactReader(rdr io.Reader) (protected, payload, signature []byte, err error) {
	data, err := jwxio.ReadAllFromFiniteSource(rdr)
	if err == nil {
		return SplitCompact(data)
	}

	if !errors.Is(err, jwxio.NonFiniteSourceError()) {
		return nil, nil, nil, err
	}

	var periods int
	var state int

	buf := make([]byte, 4096)
	var sofar []byte

	for {
		// read next bytes
		n, err := rdr.Read(buf)
		// return on unexpected read error
		if err != nil && err != io.EOF {
			return nil, nil, nil, io.ErrUnexpectedEOF
		}

		// append to current buffer
		sofar = append(sofar, buf[:n]...)
		// loop to capture multiple tokens.Period in current buffer
		for loop := true; loop; {
			var i = bytes.IndexByte(sofar, tokens.Period)
			if i == -1 && err != io.EOF {
				// no tokens.Period found -> exit and read next bytes (outer loop)
				loop = false
				continue
			} else if i == -1 && err == io.EOF {
				// no tokens.Period found -> process rest and exit
				i = len(sofar)
				loop = false
			} else {
				// tokens.Period found
				periods++
			}

			// Reaching this point means we have found a tokens.Period or EOF and process the rest of the buffer
			switch state {
			case 0:
				protected = sofar[:i]
				state++
			case 1:
				payload = sofar[:i]
				state++
			case 2:
				signature = sofar[:i]
			}
			// Shorten current buffer
			if len(sofar) > i {
				sofar = sofar[i+1:]
			}
		}
		// Exit on EOF
		if err == io.EOF {
			break
		}
	}
	if periods != 2 {
		return nil, nil, nil, InvalidNumberOfSegmentsError()
	}

	return protected, payload, signature, nil
}
