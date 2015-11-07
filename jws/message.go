package jws

import (
	"encoding/json"
	"errors"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/internal/emap"
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
	if h.Algorithm == "" {
		h.Algorithm = jwa.NoSignature
	}
	h.ContentType, _ = r.GetString("cty")
	h.KeyID, _ = r.GetString("kid")
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
			h.JwkSetURL = u
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

func (e EncodedHeader) MarshalJSON() ([]byte, error) {
	buf, err := json.Marshal(e.Header)
	if err != nil {
		return nil, err
	}

	buf, err = buffer.Buffer(buf).Base64Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(string(buf))
}

func (e *EncodedHeader) UnmarshalJSON(buf []byte) error {
	b := buffer.Buffer{}
	// base646 json string -> json object representation of header
	if err := json.Unmarshal(buf, &b); err != nil {
		return err
	}

	if err := json.Unmarshal(b.Bytes(), &e.Header); err != nil {
		return err
	}

	return nil
}

func NewSignature() *Signature {
	h1 := NewHeader()
	h2 := NewHeader()
	return &Signature{
		PublicHeader: *h1,
		ProtectedHeader: EncodedHeader{*h2},
	}
}

func (s Signature) MergedHeaders() MergedHeader {
	return MergedHeader{
		ProtectedHeader: &s.ProtectedHeader,
		PublicHeader: &s.PublicHeader,
	}
}

func (h MergedHeader) KeyID() string {
	if hp := h.ProtectedHeader; hp != nil {
		if hp.KeyID != "" {
			return hp.KeyID
		}
	}

	if hp := h.PublicHeader; hp != nil {
		if hp.KeyID != "" {
			return hp.KeyID
		}
	}

	return ""
}

func (h MergedHeader) Algorithm() jwa.SignatureAlgorithm {
	if hp := h.ProtectedHeader; hp != nil {
		return hp.Algorithm
	}
	return jwa.NoSignature
}

// LookupSignature looks up a particular signature entry using
// the `kid` value
func (m Message) LookupSignature(kid string) []Signature {
	sigs := []Signature{}
	for _, sig := range m.Signatures {
		if sig.MergedHeaders().KeyID() != kid {
			continue
		}

		sigs = append(sigs, sig)
	}
	return sigs
}

func (m Message) Verify(v Verifier) error {
	p, err := m.Payload.Base64Encode()
	if err != nil {
		return err
	}

	for _, sig := range m.Signatures {
		h, err := sig.ProtectedHeader.Base64Encode()
		if err != nil {
			return err
		}

		buf := append(append(h, '.'), p...)
		if err := v.Verify(buf, sig.Signature); err == nil {
			return nil
		}
	}

	return errors.New("none of the signatures could be verified")
}
