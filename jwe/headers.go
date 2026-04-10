package jwe

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/json"
)

type isZeroer interface {
	isZero() bool
}

func (h *stdHeaders) Clone() (Headers, error) {
	dst := &stdHeaders{}
	dst.cloneFrom(h)
	return dst, nil
}

func (h *stdHeaders) Copy(dst Headers) error {
	for _, key := range h.Keys() {
		v, ok := h.Field(key)
		if !ok {
			return fmt.Errorf(`jwe.Headers: Copy: failed to get header %q`, key)
		}
		if err := dst.Set(key, v); err != nil {
			return fmt.Errorf(`jwe.Headers: Copy: failed to set header %q: %w`, key, err)
		}
	}
	return nil
}

// copyNoLock copies all fields from h to dst without acquiring any mutexes.
// Both h and dst must be exclusively owned by the caller (not shared).
func (h *stdHeaders) copyNoLock(dst *stdHeaders) {
	dst.cloneFrom(h)
}

func (h *stdHeaders) Merge(h2 Headers) (Headers, error) {
	h3 := NewHeaders()

	if h != nil {
		if err := h.Copy(h3); err != nil {
			return nil, fmt.Errorf(`failed to copy headers from receiver: %w`, err)
		}
	}

	if h2 != nil {
		if err := h2.Copy(h3); err != nil {
			return nil, fmt.Errorf(`failed to copy headers from argument: %w`, err)
		}
	}

	return h3, nil
}

// mergeIntoNoLock copies non-nil fields from h into dst without acquiring
// any mutexes. Both h and dst must be exclusively owned by the caller.
// Unlike cloneFrom, this only overwrites fields that are set in h,
// leaving existing values in dst untouched.
func (h *stdHeaders) mergeIntoNoLock(dst *stdHeaders) {
	if h.agreementPartyUInfo != nil {
		dst.agreementPartyUInfo = h.agreementPartyUInfo
	}
	if h.agreementPartyVInfo != nil {
		dst.agreementPartyVInfo = h.agreementPartyVInfo
	}
	if h.algorithm != nil {
		dst.algorithm = h.algorithm
	}
	if h.compression != nil {
		dst.compression = h.compression
	}
	if h.contentEncryption != nil {
		dst.contentEncryption = h.contentEncryption
	}
	if h.contentType != nil {
		dst.contentType = h.contentType
	}
	if h.critical != nil {
		dst.critical = h.critical
	}
	if h.encapsulatedKey != nil {
		dst.encapsulatedKey = h.encapsulatedKey
	}
	if h.ephemeralPublicKey != nil {
		dst.ephemeralPublicKey = h.ephemeralPublicKey
	}
	if h.jwk != nil {
		dst.jwk = h.jwk
	}
	if h.jwkSetURL != nil {
		dst.jwkSetURL = h.jwkSetURL
	}
	if h.keyID != nil {
		dst.keyID = h.keyID
	}
	if h.pskID != nil {
		dst.pskID = h.pskID
	}
	if h.typ != nil {
		dst.typ = h.typ
	}
	if h.x509CertChain != nil {
		dst.x509CertChain = h.x509CertChain
	}
	if h.x509CertThumbprint != nil {
		dst.x509CertThumbprint = h.x509CertThumbprint
	}
	if h.x509CertThumbprintS256 != nil {
		dst.x509CertThumbprintS256 = h.x509CertThumbprintS256
	}
	if h.x509URL != nil {
		dst.x509URL = h.x509URL
	}
	for k, v := range h.privateParams {
		if dst.privateParams == nil {
			dst.privateParams = make(map[string]any)
		}
		dst.privateParams[k] = v
	}
}

func (h *stdHeaders) Encode() ([]byte, error) {
	buf, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf(`failed to marshal headers to JSON prior to encoding: %w`, err)
	}

	return base64.Encode(buf), nil
}

func (h *stdHeaders) Decode(buf []byte) error {
	// base64 json string -> json object representation of header
	decoded, err := base64.Decode(buf)
	if err != nil {
		return fmt.Errorf(`failed to unmarshal base64 encoded buffer: %w`, err)
	}

	if err := json.Unmarshal(decoded, h); err != nil {
		return fmt.Errorf(`failed to unmarshal buffer: %w`, err)
	}

	return nil
}
