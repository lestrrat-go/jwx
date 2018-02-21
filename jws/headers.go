package jws

import (
	"encoding/json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

const (
	AlgorithmKey              = "alg"
	ContentTypeKey            = "cty"
	CriticalKey               = "crit"
	JWKKey                    = "jwk"
	JWKSetURLKey              = "jku"
	KeyIDKey                  = "kid"
	TypeKey                   = "typ"
	X509CertChainKey          = "x5c"
	X509CertThumbprintKey     = "x5t"
	X509CertThumbprintS256Key = "x5t#S256"
	X509URLKey                = "x5u"
)

type Headers interface {
	Get(string) (interface{}, bool)
	Set(string, interface{}) error
	Algorithm() jwa.SignatureAlgorithm
	ContentType() string
	Critical() []string
	JWK() jwk.Key
	JWKSetURL() string
	KeyID() string
	Type() string
	X509CertChain() []string
	X509CertThumbprint() string
	X509CertThumbprintS256() string
	X509URL() string
}

type StandardHeaders struct {
	algorithm              *jwa.SignatureAlgorithm // https://tools.ietf.org/html/rfc7515#section-4.1.1
	contentType            *string                 // https://tools.ietf.org/html/rfc7515#section-4.1.10
	critical               []string                // https://tools.ietf.org/html/rfc7515#section-4.1.11
	jwk                    jwk.Key                 // https://tools.ietf.org/html/rfc7515#section-4.1.3
	jwkSetURL              *string                 // https://tools.ietf.org/html/rfc7515#section-4.1.2
	keyID                  *string                 // https://tools.ietf.org/html/rfc7515#section-4.1.4
	typ                    *string                 // https://tools.ietf.org/html/rfc7515#section-4.1.9
	x509CertChain          []string                // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string                 // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string                 // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string                 // https://tools.ietf.org/html/rfc7515#section-4.1.5
	privateParams          map[string]interface{}
}

func (h *StandardHeaders) Algorithm() jwa.SignatureAlgorithm {
	if v := h.algorithm; v != nil {
		return *v
	}
	return jwa.NoSignature
}

func (h *StandardHeaders) ContentType() string {
	if v := h.contentType; v != nil {
		return *v
	}
	return ""
}

func (h *StandardHeaders) Critical() []string {
	return h.critical
}

func (h *StandardHeaders) JWK() jwk.Key {
	return h.jwk
}

func (h *StandardHeaders) JWKSetURL() string {
	if v := h.jwkSetURL; v != nil {
		return *v
	}
	return ""
}

func (h *StandardHeaders) KeyID() string {
	if v := h.keyID; v != nil {
		return *v
	}
	return ""
}

func (h *StandardHeaders) Type() string {
	if v := h.typ; v != nil {
		return *v
	}
	return ""
}

func (h *StandardHeaders) X509CertChain() []string {
	return h.x509CertChain
}

func (h *StandardHeaders) X509CertThumbprint() string {
	if v := h.x509CertThumbprint; v != nil {
		return *v
	}
	return ""
}

func (h *StandardHeaders) X509CertThumbprintS256() string {
	if v := h.x509CertThumbprintS256; v != nil {
		return *v
	}
	return ""
}

func (h *StandardHeaders) X509URL() string {
	if v := h.x509URL; v != nil {
		return *v
	}
	return ""
}

func (h *StandardHeaders) Get(name string) (interface{}, bool) {
	switch name {
	case AlgorithmKey:
		v := h.algorithm
		if v == nil {
			return nil, false
		}
		return *v, true
	case ContentTypeKey:
		v := h.contentType
		if v == nil {
			return nil, false
		}
		return *v, true
	case CriticalKey:
		v := h.critical
		if v == nil {
			return nil, false
		}
		return v, true
	case JWKKey:
		v := h.jwk
		if v == nil {
			return nil, false
		}
		return v, true
	case JWKSetURLKey:
		v := h.jwkSetURL
		if v == nil {
			return nil, false
		}
		return *v, true
	case KeyIDKey:
		v := h.keyID
		if v == nil {
			return nil, false
		}
		return *v, true
	case TypeKey:
		v := h.typ
		if v == nil {
			return nil, false
		}
		return *v, true
	case X509CertChainKey:
		v := h.x509CertChain
		if v == nil {
			return nil, false
		}
		return v, true
	case X509CertThumbprintKey:
		v := h.x509CertThumbprint
		if v == nil {
			return nil, false
		}
		return *v, true
	case X509CertThumbprintS256Key:
		v := h.x509CertThumbprintS256
		if v == nil {
			return nil, false
		}
		return *v, true
	case X509URLKey:
		v := h.x509URL
		if v == nil {
			return nil, false
		}
		return *v, true
	default:
		v, ok := h.privateParams[name]
		return v, ok
	}
}

func (h *StandardHeaders) Set(name string, value interface{}) error {
	switch name {
	case AlgorithmKey:
		var acceptor jwa.SignatureAlgorithm
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, AlgorithmKey)
		}
		h.algorithm = &acceptor
		return nil
	case ContentTypeKey:
		if v, ok := value.(string); ok {
			h.contentType = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ContentTypeKey, value)
	case CriticalKey:
		if v, ok := value.([]string); ok {
			h.critical = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, CriticalKey, value)
	case JWKKey:
		if v, ok := value.(jwk.Key); ok {
			h.jwk = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, JWKKey, value)
	case JWKSetURLKey:
		if v, ok := value.(string); ok {
			h.jwkSetURL = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, JWKSetURLKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case TypeKey:
		if v, ok := value.(string); ok {
			h.typ = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, TypeKey, value)
	case X509CertChainKey:
		if v, ok := value.([]string); ok {
			h.x509CertChain = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertChainKey, value)
	case X509CertThumbprintKey:
		if v, ok := value.(string); ok {
			h.x509CertThumbprint = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertThumbprintKey, value)
	case X509CertThumbprintS256Key:
		if v, ok := value.(string); ok {
			h.x509CertThumbprintS256 = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertThumbprintS256Key, value)
	case X509URLKey:
		if v, ok := value.(string); ok {
			h.x509URL = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509URLKey, value)
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

func (h StandardHeaders) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{}
	for k, v := range h.privateParams {
		m[k] = v
	}
	m[AlgorithmKey] = h.algorithm

	if h.contentType != nil {
		m[ContentTypeKey] = h.contentType
	}

	if len(h.critical) > 0 {
		m[CriticalKey] = h.critical
	}

	if h.jwk != nil {
		m[JWKKey] = h.jwk
	}

	if h.jwkSetURL != nil {
		m[JWKSetURLKey] = h.jwkSetURL
	}

	if h.keyID != nil {
		m[KeyIDKey] = h.keyID
	}

	if h.typ != nil {
		m[TypeKey] = h.typ
	}

	if len(h.x509CertChain) > 0 {
		m[X509CertChainKey] = h.x509CertChain
	}

	if h.x509CertThumbprint != nil {
		m[X509CertThumbprintKey] = h.x509CertThumbprint
	}

	if h.x509CertThumbprintS256 != nil {
		m[X509CertThumbprintS256Key] = h.x509CertThumbprintS256
	}

	if h.x509URL != nil {
		m[X509URLKey] = h.x509URL
	}

	return json.Marshal(m)
}

func (h *StandardHeaders) UnmarshalJSON(buf []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(buf, &m); err != nil {
		return errors.Wrap(err, `failed to unmarshal headers`)
	}
	if v, ok := m[AlgorithmKey]; ok {
		if err := h.Set(AlgorithmKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, AlgorithmKey)
		}
	}
	if v, ok := m[ContentTypeKey]; ok {
		if err := h.Set(ContentTypeKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, ContentTypeKey)
		}
	}
	if v, ok := m[CriticalKey]; ok {
		if err := h.Set(CriticalKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, CriticalKey)
		}
	}
	if v, ok := m[JWKKey]; ok {
		if err := h.Set(JWKKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, JWKKey)
		}
	}
	if v, ok := m[JWKSetURLKey]; ok {
		if err := h.Set(JWKSetURLKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, JWKSetURLKey)
		}
	}
	if v, ok := m[KeyIDKey]; ok {
		if err := h.Set(KeyIDKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, KeyIDKey)
		}
	}
	if v, ok := m[TypeKey]; ok {
		if err := h.Set(TypeKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, TypeKey)
		}
	}
	if v, ok := m[X509CertChainKey]; ok {
		if err := h.Set(X509CertChainKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, X509CertChainKey)
		}
	}
	if v, ok := m[X509CertThumbprintKey]; ok {
		if err := h.Set(X509CertThumbprintKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, X509CertThumbprintKey)
		}
	}
	if v, ok := m[X509CertThumbprintS256Key]; ok {
		if err := h.Set(X509CertThumbprintS256Key, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, X509CertThumbprintS256Key)
		}
	}
	if v, ok := m[X509URLKey]; ok {
		if err := h.Set(X509URLKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, X509URLKey)
		}
	}
	h.privateParams = m
	return nil
}
