// Package jws implements the digital signature on JSON based data
// structures as described in https://tools.ietf.org/html/rfc7515
package jws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
)

func encodeSigningInputValue(hdr, payload Base64Encoder) ([]byte, error) {
	h, err := hdr.Base64Encode()
	if err != nil {
		return nil, err
	}

	p, err := payload.Base64Encode()
	if err != nil {
		return nil, err
	}

	return append(append(h, '.'), p...), nil
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
func Encode(hdr, payload Base64Encoder, signer Signer) ([]byte, error) {
	// [encoded header].[encoded payload].[signed payload]

	siv, err := encodeSigningInputValue(hdr, payload)
	if err != nil {
		return nil, err
	}

	b, err := signer.Sign(siv)
	if err != nil {
		return nil, err
	}

	enc := base64.RawURLEncoding
	out := make([]byte, enc.EncodedLen(len(b))+1)
	out[0] = '.'
	enc.Encode(out[1:], b)
	return append(siv, out...), nil
}

func Verify(hdr, payload Base64Encoder, sig []byte, verify Verifier) error {
	siv, err := encodeSigningInputValue(hdr, payload)
	if err != nil {
		return err
	}

	return verify.Verify(siv, sig)
}

func Parse(buf []byte) (*Message, error) {
	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return nil, errors.New("empty buffer")
	}

	if buf[0] == '{' {
		return parseJSON(buf)
	}
	return parseCompact(buf)
}

func ParseString(s string) (*Message, error) {
	return Parse([]byte(s))
}

func parseJSON(buf []byte) (*Message, error) {
	m := struct {
		*Message
		*Signature
	}{}

	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
	}

	// if the "signature" field exist, treat it as a flattened
	if m.Signature != nil {
		if len(m.Message.Signatures) != 0 {
			return nil, errors.New("invalid message: mixed flattened/full json serialization")
		}

		m.Message.Signatures = []Signature{*m.Signature}
	}

	for _, sig := range m.Message.Signatures {
		if sig.ProtectedHeader.Algorithm == "" {
			sig.ProtectedHeader.Algorithm = jwa.NoSignature
		}
	}

	return m.Message, nil
}

// parseCompact parses a JWS value serialized via compact serialization.
func parseCompact(buf []byte) (*Message, error) {
	parts := bytes.Split(buf, []byte{'.'})
	if len(parts) != 3 {
		return nil, ErrInvalidCompactPartsCount
	}

	enc := base64.RawURLEncoding

	hdr, err := DecodeEncodedHeader(parts[0])
	if err != nil {
		return nil, err
	}

	payload := make([]byte, enc.DecodedLen(len(parts[1])))
	if _, err := enc.Decode(payload, parts[1]); err != nil {
		return nil, err
	}
	payload = bytes.TrimRight(payload, "\x00")

	signature := make([]byte, enc.DecodedLen(len(parts[2])))
	if _, err := enc.Decode(signature, parts[2]); err != nil {
		return nil, err
	}
	signature = bytes.TrimRight(signature, "\x00")

	s := NewSignature()
	s.Signature = signature
	s.ProtectedHeader = *hdr
	m := &Message{
		Payload:    buffer.Buffer(payload),
		Signatures: []Signature{*s},
	}
	return m, nil
}
