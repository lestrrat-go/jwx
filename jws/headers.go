package jws

import (
	"encoding/json"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
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
	x509CertThumbprintKey     = "x5t"
	x509CertThumbprintS256Key = "x5t#S256"
	X509URLKey                = "x5u"
)

type StandardHeaders struct {
	algorithm              jwa.SignatureAlgorithm // https://tools.ietf.org/html/rfc7515#section-4.1.1
	contentType            string                 // https://tools.ietf.org/html/rfc7515#section-4.1.10
	critical               []string               // https://tools.ietf.org/html/rfc7515#section-4.1.11
	jwk                    jwk.Key                // https://tools.ietf.org/html/rfc7515#section-4.1.3
	jwkSetURL              string                 // https://tools.ietf.org/html/rfc7515#section-4.1.2
	keyID                  string                 // https://tools.ietf.org/html/rfc7515#section-4.1.4
	typ                    string                 // https://tools.ietf.org/html/rfc7515#section-4.1.9
	x509CertChain          []string               // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     string                 // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 string                 // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                string                 // https://tools.ietf.org/html/rfc7515#section-4.1.5
	privateParams          map[string]interface{}
}

func (h *StandardHeaders) Set(name string, value interface{}) error {
	switch name {
	case AlgorithmKey:
		if err := h.algorithm.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, AlgorithmKey)
		}
		return nil
	case ContentTypeKey:
		if v, ok := value.(string); ok {
			h.contentType = v
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
			h.jwkSetURL = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, JWKSetURLKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case TypeKey:
		if v, ok := value.(string); ok {
			h.typ = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, TypeKey, value)
	case X509CertChainKey:
		if v, ok := value.([]string); ok {
			h.x509CertChain = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertChainKey, value)
	case x509CertThumbprintKey:
		if v, ok := value.(string); ok {
			h.x509CertThumbprint = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, x509CertThumbprintKey, value)
	case x509CertThumbprintS256Key:
		if v, ok := value.(string); ok {
			h.x509CertThumbprintS256 = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, x509CertThumbprintS256Key, value)
	case X509URLKey:
		if v, ok := value.(string); ok {
			h.x509URL = v
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

	if h.contentType != "" {
		m[ContentTypeKey] = h.contentType
	}

	if len(h.critical) > 0 {
		m[CriticalKey] = h.critical
	}

	if h.jwk != nil {
		m[JWKKey] = h.jwk
	}

	if h.jwkSetURL != "" {
		m[JWKSetURLKey] = h.jwkSetURL
	}

	if h.keyID != "" {
		m[KeyIDKey] = h.keyID
	}

	if h.typ != "" {
		m[TypeKey] = h.typ
	}

	if len(h.x509CertChain) > 0 {
		m[X509CertChainKey] = h.x509CertChain
	}

	if h.x509CertThumbprint != "" {
		m[x509CertThumbprintKey] = h.x509CertThumbprint
	}

	if h.x509CertThumbprintS256 != "" {
		m[x509CertThumbprintS256Key] = h.x509CertThumbprintS256
	}

	if h.x509URL != "" {
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
		if err := h.algorithm.Accept(v); err != nil {
			return errors.Wrapf(err, `invalid value for key %s: %T`, AlgorithmKey, v)
		}
	}
	if v, ok := m[ContentTypeKey]; ok {
		if x, ok := v.(string); ok {
			h.contentType = x
			delete(m, ContentTypeKey)
		} else {
			return errors.Errorf(`invalid value for key %s: %T`, ContentTypeKey, v)
		}
	}
	if v, ok := m[CriticalKey]; ok {
		if x, ok := v.([]string); ok {
			h.critical = x
			delete(m, CriticalKey)
		} else {
			return errors.Errorf(`invalid value for key %s: %T`, CriticalKey, v)
		}
	}
	if v, ok := m[JWKKey]; ok {
		if x, ok := v.(jwk.Key); ok {
			h.jwk = x
			delete(m, JWKKey)
		} else {
			return errors.Errorf(`invalid value for key %s: %T`, JWKKey, v)
		}
	}
	if v, ok := m[JWKSetURLKey]; ok {
		if x, ok := v.(string); ok {
			h.jwkSetURL = x
			delete(m, JWKSetURLKey)
		} else {
			return errors.Errorf(`invalid value for key %s: %T`, JWKSetURLKey, v)
		}
	}
	if v, ok := m[KeyIDKey]; ok {
		if x, ok := v.(string); ok {
			h.keyID = x
			delete(m, KeyIDKey)
		} else {
			return errors.Errorf(`invalid value for key %s: %T`, KeyIDKey, v)
		}
	}
	if v, ok := m[TypeKey]; ok {
		if x, ok := v.(string); ok {
			h.typ = x
			delete(m, TypeKey)
		} else {
			return errors.Errorf(`invalid value for key %s: %T`, TypeKey, v)
		}
	}
	if v, ok := m[X509CertChainKey]; ok {
		if x, ok := v.([]string); ok {
			h.x509CertChain = x
			delete(m, X509CertChainKey)
		} else {
			return errors.Errorf(`invalid value for key %s: %T`, X509CertChainKey, v)
		}
	}
	if v, ok := m[x509CertThumbprintKey]; ok {
		if x, ok := v.(string); ok {
			h.x509CertThumbprint = x
			delete(m, x509CertThumbprintKey)
		} else {
			return errors.Errorf(`invalid value for key %s: %T`, x509CertThumbprintKey, v)
		}
	}
	if v, ok := m[x509CertThumbprintS256Key]; ok {
		if x, ok := v.(string); ok {
			h.x509CertThumbprintS256 = x
			delete(m, x509CertThumbprintS256Key)
		} else {
			return errors.Errorf(`invalid value for key %s: %T`, x509CertThumbprintS256Key, v)
		}
	}
	if v, ok := m[X509URLKey]; ok {
		if x, ok := v.(string); ok {
			h.x509URL = x
			delete(m, X509URLKey)
		} else {
			return errors.Errorf(`invalid value for key %s: %T`, X509URLKey, v)
		}
	}
	h.privateParams = m
	return nil
}
