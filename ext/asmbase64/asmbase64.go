// Package asmbase64 provides an assembly-optimized base64 backend for jwx.
//
// Import this package for its side effects to replace the default
// encoding/base64 implementation with github.com/segmentio/asm/base64:
//
//	import _ "github.com/jwx-go/asmbase64"
package asmbase64

import (
	"bytes"
	"fmt"
	"slices"

	jwx "github.com/lestrrat-go/jwx/v3"
	asmbase64 "github.com/segmentio/asm/base64"
)

func init() {
	jwx.SetBase64Encoder(asmEncoder{asmbase64.RawURLEncoding})
	jwx.SetBase64Decoder(asmDecoder{})
}

type asmEncoder struct {
	*asmbase64.Encoding
}

func (e asmEncoder) AppendEncode(dst, src []byte) []byte {
	n := e.Encoding.EncodedLen(len(src))
	dst = slices.Grow(dst, n)
	e.Encoding.Encode(dst[len(dst):][:n], src)
	return dst[:len(dst)+n]
}

type asmDecoder struct{}

func (d asmDecoder) Decode(src []byte) ([]byte, error) {
	var enc *asmbase64.Encoding
	switch guess(src) {
	case encStd:
		enc = asmbase64.StdEncoding
	case encRawStd:
		enc = asmbase64.RawStdEncoding
	case encURL:
		enc = asmbase64.URLEncoding
	case encRawURL:
		enc = asmbase64.RawURLEncoding
	default:
		return nil, fmt.Errorf(`invalid encoding`)
	}

	dst := make([]byte, enc.DecodedLen(len(src)))
	n, err := enc.Decode(dst, src)
	if err != nil {
		return nil, fmt.Errorf(`failed to decode source: %w`, err)
	}
	return dst[:n], nil
}

const (
	encInvalid = iota
	encStd
	encURL
	encRawStd
	encRawURL
)

func guess(src []byte) int {
	isRaw := !bytes.HasSuffix(src, []byte{'='})
	isURL := !bytes.ContainsAny(src, "+/")
	switch {
	case isRaw && isURL:
		return encRawURL
	case isURL:
		return encURL
	case isRaw:
		return encRawStd
	default:
		return encStd
	}
}
