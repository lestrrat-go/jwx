package jws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/emap"
	"github.com/lestrrat/go-jwx/jwa"
)

func NewHeader() *Header {
	return &Header{
		EssentialHeader: &EssentialHeader{},
		PrivateParams:   map[string]interface{}{},
	}
}

func (h Header) MarshalJSON() ([]byte, error) {
	return emap.MergeMarshal(h.EssentialHeader, h.PrivateParams)
}

func (h *Header) UnmarshalJSON(data []byte) error {
	if h.EssentialHeader == nil {
		h.EssentialHeader = &EssentialHeader{}
	}
	if h.PrivateParams == nil {
		h.PrivateParams = map[string]interface{}{}
	}
	return emap.MergeUnmarshal(data, h.EssentialHeader, &h.PrivateParams)
}

func (h *EssentialHeader) Construct(m map[string]interface{}) error {
	r := emap.Hmap(m)
	if alg, err := r.GetString("alg"); err == nil {
		h.Algorithm = jwa.SignatureAlgorithm(alg)
	}
	h.ContentType, _ = r.GetString("cty")
	h.KeyId, _ = r.GetString("kid")
	h.Type, _ = r.GetString("typ")
	h.X509CertThumbprint, _ = r.GetString("x5t")
	h.X509CertThumbprintS256, _ = r.GetString("x5t#256")
	if v, err := r.GetStringSlice("crit"); err != nil {
		h.Critical = v
	}
	if v, err := r.GetStringSlice("x5c"); err != nil {
		h.X509CertChain = v
	}
	if v, err := r.GetString("jku"); err == nil {
		u, err := url.Parse(v)
		if err == nil {
			h.JwkSetUrl = u
		}
	}

	if v, err := r.GetString("x5u"); err == nil {
		u, err := url.Parse(v)
		if err == nil {
			h.X509Url = u
		}
	}

	return nil
}

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

func Parse(buf []byte) (*Message, error) {
	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return nil, errors.New("empty buffer")
	}

	if buf[0] == '{' {
		return ParseJSON(buf)
	}
	return ParseCompact(buf)
}

func ParseJSON(buf []byte) (*Message, error) {
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

	return m.Message, nil
}

// ParseCompact parses a JWS value serialized via compact serialization.
func ParseCompact(buf []byte) (*Message, error) {
	parts := bytes.Split(buf, []byte{'.'})
	if len(parts) != 3 {
		return nil, ErrInvalidCompactPartsCount
	}

	enc := base64.RawURLEncoding

	p0Len := enc.DecodedLen(len(parts[0]))
	p1Len := enc.DecodedLen(len(parts[1]))
	p2Len := enc.DecodedLen(len(parts[2]))

	out := make([]byte, p0Len+p1Len+p2Len)

	hdrbuf := buffer.Buffer(out[:p0Len])
	if _, err := enc.Decode(hdrbuf, parts[0]); err != nil {
		return nil, err
	}
	hdrbuf = bytes.TrimRight(hdrbuf, "\x00")

	payload := out[p0Len : p0Len+p1Len]
	if _, err := enc.Decode(payload, parts[1]); err != nil {
		return nil, err
	}
	payload = bytes.TrimRight(payload, "\x00")

	signature := out[p0Len+p1Len-1 : p0Len+p1Len+p2Len]
	if _, err := enc.Decode(signature, parts[2]); err != nil {
		return nil, err
	}
	signature = bytes.TrimRight(signature, "\x00")

	hdr := NewHeader()
	if err := json.Unmarshal(hdrbuf, hdr); err != nil {
		return nil, err
	}

	m := &Message{
		Payload: buffer.Buffer(payload),
		Signatures: []Signature{
			Signature{
				Header:    *hdr,
				Signature: signature,
			},
		},
	}
	return m, nil
}
