package jws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

	"github.com/lestrrat/go-jwx/buffer"
)

func (h Header) Base64Encode() ([]byte, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}

	return buffer.Buffer(b).Base64Encode()
}

// Encode takes a header, a payload, and a signer, and produces a signed
// compact serialization format of the given header and payload.
//
// The header and the payload need only be able to produce the base64
// encoded version of itself for flexibility.
//
// The signer can be anything that implements the Signer interface.
//
// See also: Compact Serialization https://tools.ietf.org/html/rfc7515#section-3.1
func Encode(hdr Base64Encoder, payload Base64Encoder, signer Signer) ([]byte, error) {
	// [encoded header].[encoded payload].[signed payload]

	h, err := hdr.Base64Encode()
	if err != nil {
		return nil, err
	}

	p, err := payload.Base64Encode()
	if err != nil {
		return nil, err
	}

	ss := append(append(h, '.'), p...)

	b, err := signer.Sign(ss)
	if err != nil {
		return nil, err
	}

	enc := base64.RawURLEncoding
	out := make([]byte, enc.EncodedLen(len(b))+1)
	out[0] = '.'
	enc.Encode(out[1:], b)
	ss = append(ss, out...)

	return ss, nil
}

// ParseCompact parses a JWS value serialized via compact serialization.
func ParseCompact(buf []byte) (*Compact, error) {
	parts := bytes.Split(buf, []byte{'.'})
	if len(parts) != 3 {
		return nil, ErrInvalidCompactPartsCount
	}

	enc := base64.RawURLEncoding

	p0Len := enc.DecodedLen(len(parts[0]))
	p1Len := enc.DecodedLen(len(parts[1]))
	p2Len := enc.DecodedLen(len(parts[2]))

	out := make([]byte, p0Len+p1Len+p2Len)

	c := Compact{}
	c.Header = buffer.Buffer(out[:p0Len])
	if _, err := enc.Decode(c.Header, parts[0]); err != nil {
		return nil, err
	}
	c.Header = bytes.TrimRight(c.Header, "\x00")

	c.Payload = out[p0Len : p0Len+p1Len]
	if _, err := enc.Decode(c.Payload, parts[1]); err != nil {
		return nil, err
	}
	c.Payload = bytes.TrimRight(c.Payload, "\x00")

	c.Signature = out[p0Len+p1Len-1 : p0Len+p1Len+p2Len]
	if _, err := enc.Decode(c.Signature, parts[2]); err != nil {
		return nil, err
	}
	c.Signature = bytes.TrimRight(c.Signature, "\x00")

	return &c, nil
}
