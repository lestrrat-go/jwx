package jwe

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/internal/base64"
	"github.com/lestrrat-go/jwx/v2/internal/json"
)

type isZeroer interface {
	isZero() bool
}

func (h *stdHeaders) isZero() bool {
	return h.agreementPartyUInfo == nil &&
		h.agreementPartyVInfo == nil &&
		h.algorithm == nil &&
		h.compression == nil &&
		h.contentEncryption == nil &&
		h.contentType == nil &&
		h.critical == nil &&
		h.ephemeralPublicKey == nil &&
		h.jwk == nil &&
		h.jwkSetURL == nil &&
		h.keyID == nil &&
		h.typ == nil &&
		h.x509CertChain == nil &&
		h.x509CertThumbprint == nil &&
		h.x509CertThumbprintS256 == nil &&
		h.x509URL == nil &&
		len(h.extra) == 0
}

func (v *stdHeaders) Copy(dst Headers) error {
	for _, key := range v.Keys() {
		var val interface{}
		if err := v.Get(key, &val); err != nil {
			return fmt.Errorf(`failed to get header %q during copy: %w`, key, err)
		}

		if err := dst.Set(key, val); err != nil {
			return fmt.Errorf(`failed to set header %q during copy: %w`, key, err)
		}
	}
	return nil
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
