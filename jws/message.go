package jws

import (
	"encoding/base64"

	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/pkg/errors"
)

func (s Signature) PublicHeaders() Headers {
	return s.headers
}

func (s Signature) ProtectedHeaders() Headers {
	return s.protected
}

func (s Signature) Signature() []byte {
	return s.signature
}

func (m Message) Payload() []byte {
	return m.payload
}

func (m Message) Signatures() []*Signature {
	return m.signatures
}

// LookupSignature looks up a particular signature entry using
// the `kid` value
func (m Message) LookupSignature(kid string) []*Signature {
	var sigs []*Signature
	for _, sig := range m.signatures {
		if hdr := sig.PublicHeaders(); hdr != nil {
			hdrKeyID := hdr.KeyID()
			if hdrKeyID == kid {
				sigs = append(sigs, sig)
				continue
			}
		}

		if hdr := sig.ProtectedHeaders(); hdr != nil {
			hdrKeyID := hdr.KeyID()
			if hdrKeyID == kid {
				sigs = append(sigs, sig)
				continue
			}
		}
	}
	return sigs
}

type messageProxy struct {
	Payload    string            `json:"payload"` // base64 URL encoded
	Signatures []*signatureProxy `json:"signatures,omitempty"`

	// These are only available when we're using flattened JSON
	// (normally I would embed *signatureProxy, but because
	// signatureProxy is not exported, we can't use that)
	Header    *json.RawMessage `json:"header,omitempty"`
	Protected *string          `json:"protected,omitempty"`
	Signature *string          `json:"signature,omitempty"`
}

type signatureProxy struct {
	Header    json.RawMessage `json:"header"`
	Protected string          `json:"protected"`
	Signature string          `json:"signature"`
}

func (m *Message) UnmarshalJSON(buf []byte) error {
	var proxy messageProxy
	if err := json.Unmarshal(buf, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmarshal into temporary structure`)
	}

	// Everything in the proxy is base64 encoded, except for signatures.header
	enc := base64.RawURLEncoding

	if len(proxy.Payload) == 0 {
		return errors.New(`"payload" must be non-empty`)
	}

	buf, err := enc.DecodeString(proxy.Payload)
	if err != nil {
		return errors.Wrap(err, `failed to decode payload`)
	}
	m.payload = buf

	if proxy.Signature != nil {
		if len(proxy.Signatures) > 0 {
			return errors.Wrap(err, `invalid format ("signatures" and "signature" keys cannot both be present)`)
		}

		var sigproxy signatureProxy
		if hdr := proxy.Header; hdr != nil {
			sigproxy.Header = *hdr
		}
		if hdr := proxy.Protected; hdr != nil {
			sigproxy.Protected = *hdr
		}
		sigproxy.Signature = *proxy.Signature

		proxy.Signatures = append(proxy.Signatures, &sigproxy)
	}

	for i, sigproxy := range proxy.Signatures {
		var sig Signature

		if len(sigproxy.Header) > 0 {
			sig.headers = NewHeaders()
			if err := json.Unmarshal(sigproxy.Header, sig.headers); err != nil {
				return errors.Wrapf(err, `failed to unmarshal "header" for signature #%d`, i+1)
			}
		}

		if len(sigproxy.Protected) > 0 {
			buf, err = enc.DecodeString(sigproxy.Protected)
			if err != nil {
				return errors.Wrapf(err, `failed to decode "protected" for signature #%d`, i+1)
			}
			sig.protected = NewHeaders()
			if err := json.Unmarshal(buf, sig.protected); err != nil {
				return errors.Wrapf(err, `failed to unmarshal "protected" for signature #%d`, i+1)
			}
		}

		if len(sigproxy.Signature) == 0 {
			return errors.Errorf(`"signature" must be non-empty for signature #%d`, i+1)
		}

		buf, err = enc.DecodeString(sigproxy.Signature)
		if err != nil {
			return errors.Wrapf(err, `failed to decode "signature" for signature #%d`, i+1)
		}
		sig.signature = buf
		m.signatures = append(m.signatures, &sig)
	}

	return nil
}

func (m Message) MarshalJSON() ([]byte, error) {
	var proxy messageProxy

	enc := base64.RawURLEncoding
	proxy.Payload = enc.EncodeToString(m.payload)

	if len(m.signatures) == 1 {
		sig := m.signatures[0]
		var s = string(sig.signature)
		proxy.Signature = &s

		buf, err := json.Marshal(sig.headers)
		if err != nil {
			return nil, errors.Wrap(err, `failed to marshal "header"`)
		}
		hdr := json.RawMessage(buf)
		proxy.Header = &hdr

		buf, err = json.Marshal(sig.protected)
		if err != nil {
			return nil, errors.Wrap(err, `failed to marshal "protected"`)
		}
		protected := enc.EncodeToString(buf)
		proxy.Protected = &protected
	} else {
		for i, sig := range m.signatures {
			var sigproxy signatureProxy

			buf, err := json.Marshal(sig.headers)
			if err != nil {
				return nil, errors.Wrapf(err, `failed to marshal "header" for signature #%d`, i+1)
			}
			sigproxy.Header = buf

			buf, err = json.Marshal(sig.protected)
			if err != nil {
				return nil, errors.Wrapf(err, `failed to marshal "protected" for signature #%d`, i+1)
			}
			sigproxy.Protected = enc.EncodeToString(buf)
			sigproxy.Signature = enc.EncodeToString(sig.signature)

			proxy.Signatures = append(proxy.Signatures, &sigproxy)
		}
	}

	return json.Marshal(proxy)
}
