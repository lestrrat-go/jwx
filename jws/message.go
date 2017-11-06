package jws

import (
	"encoding/json"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/internal/emap"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/pkg/errors"
)

// NewHeader creates a new Header
func NewHeader() *Header {
	return &Header{
		EssentialHeader: &EssentialHeader{},
		PrivateParams:   map[string]interface{}{},
	}
}

// Set sets the value of the given key to the given value. If it's
// one of the known keys, it will be set in EssentialHeader field.
// Otherwise, it is set in PrivateParams field.
func (h *Header) Set(key string, value interface{}) error {
	switch key {
	case "alg":
		var v jwa.SignatureAlgorithm
		s, ok := value.(string)
		if ok {
			v = jwa.SignatureAlgorithm(s)
		} else {
			v, ok = value.(jwa.SignatureAlgorithm)
			if !ok {
				return ErrInvalidHeaderValue
			}
		}
		h.Algorithm = v
	case "cty":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.ContentType = v
	case "kid":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.KeyID = v
	case "typ":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.Type = v
	case "x5t":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertThumbprint = v
	case "x5t#256":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertThumbprintS256 = v
	case "x5c":
		v, ok := value.([]string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertChain = v
	case "crit":
		v, ok := value.([]string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.Critical = v
	case "jwk":
		v, ok := value.(jwk.Key)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.Jwk = v
	case "jku":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		u, err := url.Parse(v)
		if err != nil {
			return ErrInvalidHeaderValue
		}
		h.JwkSetURL = u
	case "x5u":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		u, err := url.Parse(v)
		if err != nil {
			return ErrInvalidHeaderValue
		}
		h.X509Url = u
	default:
		h.PrivateParams[key] = value
	}
	return nil
}

// Merge merges the current header with another.
func (h *Header) Merge(h2 *Header) (*Header, error) {
	if h2 == nil {
		return nil, errors.New("merge target is nil")
	}

	h3 := NewHeader()
	if err := h3.Copy(h); err != nil {
		return nil, errors.Wrap(err, `failed to copy headers`)
	}

	h3.EssentialHeader.Merge(h2.EssentialHeader)

	for k, v := range h2.PrivateParams {
		h3.PrivateParams[k] = v
	}

	return h3, nil
}

// Merge merges the current header with another.
func (h *EssentialHeader) Merge(h2 *EssentialHeader) {
	if h2.Algorithm != "" {
		h.Algorithm = h2.Algorithm
	}

	if h2.ContentType != "" {
		h.ContentType = h2.ContentType
	}

	if h2.Jwk != nil {
		h.Jwk = h2.Jwk
	}

	if h2.JwkSetURL != nil {
		h.JwkSetURL = h2.JwkSetURL
	}

	if h2.KeyID != "" {
		h.KeyID = h2.KeyID
	}

	if h2.Type != "" {
		h.Type = h2.Type
	}

	if h2.X509Url != nil {
		h.X509Url = h2.X509Url
	}

	if h2.X509CertChain != nil {
		h.X509CertChain = h2.X509CertChain
	}

	if h2.X509CertThumbprint != "" {
		h.X509CertThumbprint = h2.X509CertThumbprint
	}

	if h2.X509CertThumbprintS256 != "" {
		h.X509CertThumbprintS256 = h2.X509CertThumbprintS256
	}
}

// Copy copies the other heder over this one
func (h *Header) Copy(h2 *Header) error {
	if h == nil {
		return errors.New("copy destination is nil")
	}
	if h2 == nil {
		return errors.New("copy target is nil")
	}

	h.EssentialHeader.Copy(h2.EssentialHeader)

	for k, v := range h2.PrivateParams {
		h.PrivateParams[k] = v
	}

	return nil
}

// Copy copies the other heder over this one
func (h *EssentialHeader) Copy(h2 *EssentialHeader) {
	h.Algorithm = h2.Algorithm
	h.ContentType = h2.ContentType
	h.Jwk = h2.Jwk
	h.JwkSetURL = h2.JwkSetURL
	h.KeyID = h2.KeyID
	h.Type = h2.Type
	h.X509Url = h2.X509Url
	h.X509CertChain = h2.X509CertChain
	h.X509CertThumbprint = h2.X509CertThumbprint
	h.X509CertThumbprintS256 = h2.X509CertThumbprintS256
}

// MarshalJSON generates the JSON representation of this header
func (h Header) MarshalJSON() ([]byte, error) {
	return emap.MergeMarshal(h.EssentialHeader, h.PrivateParams)
}

// UnmarshalJSON parses the JSON buffer into a Header
func (h *Header) UnmarshalJSON(data []byte) error {
	if h.EssentialHeader == nil {
		h.EssentialHeader = &EssentialHeader{}
	}
	if h.PrivateParams == nil {
		h.PrivateParams = map[string]interface{}{}
	}
	return emap.MergeUnmarshal(data, h.EssentialHeader, &h.PrivateParams)
}

// Construct walks through the map (most likely parsed from a JSON buffer)
// and populates the necessary fields on this header
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
	if v, err := r.GetByteSlice("jwk"); err == nil {
		if jwks, err := jwk.Parse(v); err == nil {
			if len(jwks.Keys) != 1 {
				// The spec says "a JWK", so I believe this should represent
				// one JWK. check for that, and if not, return an error because
				// the JWS is probably invalid (XXX: send in a PR if there are
				// cases where this must work in the wild)
				return errors.New("expected a single JWK in this field")
			}
			h.Jwk = jwks.Keys[0]
		}
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

// Base64Encode creates the base64 encoded version of the JSON
// representation of this header
func (h Header) Base64Encode() ([]byte, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal header`)
	}

	return buffer.Buffer(b).Base64Encode()
}

// MarshalJSON generates the JSON representation of this header
func (e EncodedHeader) MarshalJSON() ([]byte, error) {
	buf, err := json.Marshal(e.Header)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal raw header`)
	}

	buf, err = buffer.Buffer(buf).Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, `failed to base64 encode header`)
	}

	data, err := json.Marshal(string(buf))
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal encoded header value`)
	}
	return data, nil
}

// UnmarshalJSON parses the JSON buffer into a Header
func (e *EncodedHeader) UnmarshalJSON(buf []byte) error {
	b := buffer.Buffer{}
	// base646 json string -> json object representation of header
	if err := json.Unmarshal(buf, &b); err != nil {
		return errors.Wrap(err, `failed to unmarshal encoded header`)
	}

	if err := json.Unmarshal(b.Bytes(), &e.Header); err != nil {
		return errors.Wrap(err, `failed to unmarshal decoded header`)
	}

	e.Source = b

	return nil
}

// NewSignature creates a new Signature
func NewSignature() *Signature {
	h1 := NewHeader()
	h2 := NewHeader()
	return &Signature{
		PublicHeader:    h1,
		ProtectedHeader: &EncodedHeader{Header: h2},
	}
}

// MergedHeaders returns the merged header for this signature
func (s Signature) MergedHeaders() MergedHeader {
	return MergedHeader{
		ProtectedHeader: s.ProtectedHeader,
		PublicHeader:    s.PublicHeader,
	}
}

// KeyID returns the key ID (kid) for this signature
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

// Algorithm returns the algorithm used for this signature
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
