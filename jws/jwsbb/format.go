package jwsbb

import (
	"bytes"
	"errors"
	"io"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/jwxio"
	"github.com/lestrrat-go/jwx/v3/internal/tokens"
)

// SignBuffer combines the base64-encodedheader and payload into
// a single byte slice. The result can be passed to the various
// SignXXXXCompact() functions to create a JWS signature.
func SignBuffer(buf, hdr, payload []byte, encoder base64.Encoder, encodePayload bool) []byte {
	l := encoder.EncodedLen(len(hdr)+len(payload)) + 1
	if cap(buf) < l {
		buf = make([]byte, 0, l)
	}
	buf = buf[:0]
	buf = encoder.AppendEncode(buf, hdr)
	buf = append(buf, tokens.Period)
	if encodePayload {
		buf = encoder.AppendEncode(buf, payload)
	} else {
		buf = append(buf, payload...)
	}

	return buf
}

// AppendSignature appends the signature to the compactly serialized JWS
// that consists of the header and payload. The signature is appended
// in Base64URL format, and a period ('.') is added before the signature.
func AppendSignature(buf, signature []byte, encoder base64.Encoder) []byte {
	l := len(buf) + len(signature) + 1
	if cap(buf) < l {
		buf = make([]byte, 0, l)
	}
	buf = append(buf, tokens.Period)
	buf = encoder.AppendEncode(buf, signature)

	return buf
}

// JoinCompact combines the header, payload, and signature into a single byte slice,
// using the specified base64.Encoder to encode the components.
func JoinCompact(buf, hdr, payload, signature []byte, encoder base64.Encoder, encodePayload bool) []byte {
	l := len(hdr) + len(payload) + len(signature) + 2
	if cap(buf) < l {
		buf = make([]byte, 0, l)
	}
	buf = buf[:0]
	buf = encoder.AppendEncode(buf, hdr)
	buf = append(buf, tokens.Period)
	if encodePayload {
		buf = encoder.AppendEncode(buf, payload)
	} else {
		buf = append(buf, payload...)
	}
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
