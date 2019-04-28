// This file is auto-generated. DO NOT EDIT
package jws

import (
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
	PrivateParamsKey          = "privateParams"
	TypeKey                   = "typ"
	X509CertChainKey          = "x5c"
	X509CertThumbprintKey     = "x5t"
	X509CertThumbprintS256Key = "x5t#S256"
	X509URLKey                = "x5u"
)

type Headers interface {
	Get(string) (interface{}, bool)
	Set(string, interface{}) error
	GetAlgorithm() jwa.SignatureAlgorithm
}

type StandardHeaders struct {
	Algorithm              jwa.SignatureAlgorithm `json:"alg,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.1
	ContentType            string                 `json:"cty,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.10
	Critical               []string               `json:"crit,omitempty"`          // https://tools.ietf.org/html/rfc7515#section-4.1.11
	JWK                    *jwk.Set               `json:"jwk,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.3
	JWKSetURL              string                 `json:"jku,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.2
	KeyID                  string                 `json:"kid,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	PrivateParams          map[string]interface{} `json:"privateParams,omitempty"` // https://tools.ietf.org/html/rfc7515#section-4.1.9
	Type                   string                 `json:"typ,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.9
	X509CertChain          []string               `json:"x5c,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.6
	X509CertThumbprint     string                 `json:"x5t,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.7
	X509CertThumbprintS256 string                 `json:"x5t#S256,omitempty"`      // https://tools.ietf.org/html/rfc7515#section-4.1.8
	X509URL                string                 `json:"x5u,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.5
}

func (h *StandardHeaders) GetAlgorithm() jwa.SignatureAlgorithm {
	return h.Algorithm
}

func (h *StandardHeaders) Get(name string) (interface{}, bool) {
	switch name {
	case AlgorithmKey:
		v := h.Algorithm
		if v == "" {
			return nil, false
		}
		return v, true
	case ContentTypeKey:
		v := h.ContentType
		if v == "" {
			return nil, false
		}
		return v, true
	case CriticalKey:
		v := h.Critical
		if len(v) == 0 {
			return nil, false
		}
		return v, true
	case JWKKey:
		v := h.JWK
		if v == nil {
			return nil, false
		}
		return v, true
	case JWKSetURLKey:
		v := h.JWKSetURL
		if v == "" {
			return nil, false
		}
		return v, true
	case KeyIDKey:
		v := h.KeyID
		if v == "" {
			return nil, false
		}
		return v, true
	case PrivateParamsKey:
		v := h.PrivateParams
		if v == nil {
			return nil, false
		}
		return v, true
	case TypeKey:
		v := h.Type
		if v == "" {
			return nil, false
		}
		return v, true
	case X509CertChainKey:
		v := h.X509CertChain
		if len(v) == 0 {
			return nil, false
		}
		return v, true
	case X509CertThumbprintKey:
		v := h.X509CertThumbprint
		if v == "" {
			return nil, false
		}
		return v, true
	case X509CertThumbprintS256Key:
		v := h.X509CertThumbprintS256
		if v == "" {
			return nil, false
		}
		return v, true
	case X509URLKey:
		v := h.X509URL
		if v == "" {
			return nil, false
		}
		return v, true
	default:
		v, ok := h.PrivateParams[name]
		return v, ok
	}
}

func (h *StandardHeaders) Set(name string, value interface{}) error {
	switch name {
	case AlgorithmKey:
		if err := h.Algorithm.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, AlgorithmKey)
		}
		return nil
	case ContentTypeKey:
		if v, ok := value.(string); ok {
			h.ContentType = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ContentTypeKey, value)
	case CriticalKey:
		if v, ok := value.([]string); ok {
			h.Critical = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, CriticalKey, value)
	case JWKKey:
		if v, ok := value.(*jwk.Set); ok {
			h.JWK = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, JWKKey, value)
	case JWKSetURLKey:
		if v, ok := value.(string); ok {
			h.JWKSetURL = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, JWKSetURLKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.KeyID = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case PrivateParamsKey:
		if v, ok := value.(map[string]interface{}); ok {
			h.PrivateParams = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, PrivateParamsKey, value)
	case TypeKey:
		if v, ok := value.(string); ok {
			h.Type = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, TypeKey, value)
	case X509CertChainKey:
		if v, ok := value.([]string); ok {
			h.X509CertChain = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertChainKey, value)
	case X509CertThumbprintKey:
		if v, ok := value.(string); ok {
			h.X509CertThumbprint = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertThumbprintKey, value)
	case X509CertThumbprintS256Key:
		if v, ok := value.(string); ok {
			h.X509CertThumbprintS256 = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertThumbprintS256Key, value)
	case X509URLKey:
		if v, ok := value.(string); ok {
			h.X509URL = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509URLKey, value)
	default:
		if h.PrivateParams == nil {
			h.PrivateParams = map[string]interface{}{}
		}
		h.PrivateParams[name] = value
	}
	return nil
}
