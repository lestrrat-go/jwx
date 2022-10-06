package jwe

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/internal/base64"
	"github.com/lestrrat-go/jwx/v2/internal/json"
)

type isZeroer interface {
	isZero() bool
}

func (v *stdHeaders) isZero() bool {
	return v.agreementPartyUInfo == nil &&
		v.agreementPartyVInfo == nil &&
		v.algorithm == nil &&
		v.compression == nil &&
		v.contentEncryption == nil &&
		v.contentType == nil &&
		v.critical == nil &&
		v.ephemeralPublicKey == nil &&
		v.jwk == nil &&
		v.jwkSetURL == nil &&
		v.keyID == nil &&
		v.typ == nil &&
		v.x509CertChain == nil &&
		v.x509CertThumbprint == nil &&
		v.x509CertThumbprintS256 == nil &&
		v.x509URL == nil &&
		len(v.extra) == 0
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

func (v *stdHeaders) Merge(h2 Headers) (Headers, error) {
	h3 := NewHeaders()

	if v != nil {
		if err := v.Copy(h3); err != nil {
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

func (v *stdHeaders) Encode() ([]byte, error) {
	buf, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf(`failed to marshal headers to JSON prior to encoding: %w`, err)
	}

	return base64.Encode(buf), nil
}

func (v *stdHeaders) Decode(buf []byte) error {
	// base64 json string -> json object representation of header
	decoded, err := base64.Decode(buf)
	if err != nil {
		return fmt.Errorf(`failed to unmarshal base64 encoded buffer: %w`, err)
	}

	if err := json.Unmarshal(decoded, v); err != nil {
		return fmt.Errorf(`failed to unmarshal buffer: %w`, err)
	}

	return nil
}
