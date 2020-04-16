// This file is auto-generated. DO NOT EDIT
package jws

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

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

// Headers describe a standard Header set.
type Headers interface {
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
	Iterate(ctx context.Context) Iterator
	Walk(ctx context.Context, v Visitor) error
	AsMap(ctx context.Context) (map[string]interface{}, error)
	Get(string) (interface{}, bool)
	Set(string, interface{}) error
}

type stdHeaders struct {
	algorithm              jwa.SignatureAlgorithm `json:"alg,omitempty"`      // https://tools.ietf.org/html/rfc7515#section-4.1.1
	contentType            string                 `json:"cty,omitempty"`      // https://tools.ietf.org/html/rfc7515#section-4.1.10
	critical               []string               `json:"crit,omitempty"`     // https://tools.ietf.org/html/rfc7515#section-4.1.11
	jwk                    jwk.Key                `json:"jwk,omitempty"`      // https://tools.ietf.org/html/rfc7515#section-4.1.3
	jwkSetURL              string                 `json:"jku,omitempty"`      // https://tools.ietf.org/html/rfc7515#section-4.1.2
	keyID                  string                 `json:"kid,omitempty"`      // https://tools.ietf.org/html/rfc7515#section-4.1.4
	typ                    string                 `json:"typ,omitempty"`      // https://tools.ietf.org/html/rfc7515#section-4.1.9
	x509CertChain          []string               `json:"x5c,omitempty"`      // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     string                 `json:"x5t,omitempty"`      // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 string                 `json:"x5t#S256,omitempty"` // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                string                 `json:"x5u,omitempty"`      // https://tools.ietf.org/html/rfc7515#section-4.1.5
	privateParams          map[string]interface{}
}

type standardHeadersMarshalProxy struct {
	Xalgorithm              jwa.SignatureAlgorithm `json:"alg,omitempty"`
	XcontentType            string                 `json:"cty,omitempty"`
	Xcritical               []string               `json:"crit,omitempty"`
	Xjwk                    json.RawMessage        `json:"jwk,omitempty"`
	XjwkSetURL              string                 `json:"jku,omitempty"`
	XkeyID                  string                 `json:"kid,omitempty"`
	Xtyp                    string                 `json:"typ,omitempty"`
	Xx509CertChain          []string               `json:"x5c,omitempty"`
	Xx509CertThumbprint     string                 `json:"x5t,omitempty"`
	Xx509CertThumbprintS256 string                 `json:"x5t#S256,omitempty"`
	Xx509URL                string                 `json:"x5u,omitempty"`
}

func NewHeaders() Headers {
	return &stdHeaders{}
}

func (h *stdHeaders) Algorithm() jwa.SignatureAlgorithm {
	return h.algorithm
}

func (h *stdHeaders) ContentType() string {
	return h.contentType
}

func (h *stdHeaders) Critical() []string {
	return h.critical
}

func (h *stdHeaders) JWK() jwk.Key {
	return h.jwk
}

func (h *stdHeaders) JWKSetURL() string {
	return h.jwkSetURL
}

func (h *stdHeaders) KeyID() string {
	return h.keyID
}

func (h *stdHeaders) Type() string {
	return h.typ
}

func (h *stdHeaders) X509CertChain() []string {
	return h.x509CertChain
}

func (h *stdHeaders) X509CertThumbprint() string {
	return h.x509CertThumbprint
}

func (h *stdHeaders) X509CertThumbprintS256() string {
	return h.x509CertThumbprintS256
}

func (h *stdHeaders) X509URL() string {
	return h.x509URL
}

func (h *stdHeaders) iterate(ctx context.Context, ch chan *HeaderPair) {
	defer close(ch)
	var pairs []*HeaderPair
	if h.algorithm != "" {
		pairs = append(pairs, &HeaderPair{Key: AlgorithmKey, Value: h.algorithm})
	}
	if h.contentType != "" {
		pairs = append(pairs, &HeaderPair{Key: ContentTypeKey, Value: h.contentType})
	}
	if len(h.critical) > 0 {
		pairs = append(pairs, &HeaderPair{Key: CriticalKey, Value: h.critical})
	}
	if h.jwk != nil {
		pairs = append(pairs, &HeaderPair{Key: JWKKey, Value: h.jwk})
	}
	if h.jwkSetURL != "" {
		pairs = append(pairs, &HeaderPair{Key: JWKSetURLKey, Value: h.jwkSetURL})
	}
	if h.keyID != "" {
		pairs = append(pairs, &HeaderPair{Key: KeyIDKey, Value: h.keyID})
	}
	if h.typ != "" {
		pairs = append(pairs, &HeaderPair{Key: TypeKey, Value: h.typ})
	}
	if len(h.x509CertChain) > 0 {
		pairs = append(pairs, &HeaderPair{Key: X509CertChainKey, Value: h.x509CertChain})
	}
	if h.x509CertThumbprint != "" {
		pairs = append(pairs, &HeaderPair{Key: X509CertThumbprintKey, Value: h.x509CertThumbprint})
	}
	if h.x509CertThumbprintS256 != "" {
		pairs = append(pairs, &HeaderPair{Key: X509CertThumbprintS256Key, Value: h.x509CertThumbprintS256})
	}
	if h.x509URL != "" {
		pairs = append(pairs, &HeaderPair{Key: X509URLKey, Value: h.x509URL})
	}
	for k, v := range h.privateParams {
		pairs = append(pairs, &HeaderPair{Key: k, Value: v})
	}
	for _, pair := range pairs {
		select {
		case <-ctx.Done():
			return
		case ch <- pair:
		}
	}
}

func (h *stdHeaders) PrivateParams() map[string]interface{} {
	return h.privateParams
}

func (h *stdHeaders) Get(name string) (interface{}, bool) {
	switch name {
	case AlgorithmKey:
		v := h.algorithm
		if v == "" {
			return nil, false
		}
		return v, true
	case ContentTypeKey:
		v := h.contentType
		if v == "" {
			return nil, false
		}
		return v, true
	case CriticalKey:
		v := h.critical
		if len(v) == 0 {
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
		if v == "" {
			return nil, false
		}
		return v, true
	case KeyIDKey:
		v := h.keyID
		if v == "" {
			return nil, false
		}
		return v, true
	case TypeKey:
		v := h.typ
		if v == "" {
			return nil, false
		}
		return v, true
	case X509CertChainKey:
		v := h.x509CertChain
		if len(v) == 0 {
			return nil, false
		}
		return v, true
	case X509CertThumbprintKey:
		v := h.x509CertThumbprint
		if v == "" {
			return nil, false
		}
		return v, true
	case X509CertThumbprintS256Key:
		v := h.x509CertThumbprintS256
		if v == "" {
			return nil, false
		}
		return v, true
	case X509URLKey:
		v := h.x509URL
		if v == "" {
			return nil, false
		}
		return v, true
	default:
		v, ok := h.privateParams[name]
		return v, ok
	}
}

func (h *stdHeaders) Set(name string, value interface{}) error {
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
		v, ok := value.(jwk.Key)
		if ok {
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
	case X509CertThumbprintKey:
		if v, ok := value.(string); ok {
			h.x509CertThumbprint = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertThumbprintKey, value)
	case X509CertThumbprintS256Key:
		if v, ok := value.(string); ok {
			h.x509CertThumbprintS256 = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertThumbprintS256Key, value)
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

func (h *stdHeaders) UnmarshalJSON(buf []byte) error {
	var proxy standardHeadersMarshalProxy
	if err := json.Unmarshal(buf, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmarshal headers`)
	}

	h.jwk = nil
	if jwkField := proxy.Xjwk; len(jwkField) > 0 {
		set, err := jwk.ParseBytes([]byte(proxy.Xjwk))
		if err != nil {
			return errors.Wrap(err, `failed to parse jwk field`)
		}
		h.jwk = set.Keys[0]
	}
	h.algorithm = proxy.Xalgorithm
	h.contentType = proxy.XcontentType
	h.critical = proxy.Xcritical
	h.jwkSetURL = proxy.XjwkSetURL
	h.keyID = proxy.XkeyID
	h.typ = proxy.Xtyp
	h.x509CertChain = proxy.Xx509CertChain
	h.x509CertThumbprint = proxy.Xx509CertThumbprint
	h.x509CertThumbprintS256 = proxy.Xx509CertThumbprintS256
	h.x509URL = proxy.Xx509URL
	var m map[string]interface{}
	if err := json.Unmarshal(buf, &m); err != nil {
		return errors.Wrap(err, `failed to parse privsate parameters`)
	}
	delete(m, AlgorithmKey)
	delete(m, ContentTypeKey)
	delete(m, CriticalKey)
	delete(m, JWKKey)
	delete(m, JWKSetURLKey)
	delete(m, KeyIDKey)
	delete(m, TypeKey)
	delete(m, X509CertChainKey)
	delete(m, X509CertThumbprintKey)
	delete(m, X509CertThumbprintS256Key)
	delete(m, X509URLKey)
	h.privateParams = m
	return nil
}

func (h stdHeaders) MarshalJSON() ([]byte, error) {
	var proxy standardHeadersMarshalProxy
	if h.jwk != nil {
		jwkbuf, err := json.Marshal(h.jwk)
		if err != nil {
			return nil, errors.Wrap(err, `failed to marshal jwk field`)
		}
		proxy.Xjwk = jwkbuf
	}
	proxy.Xalgorithm = h.algorithm
	proxy.XcontentType = h.contentType
	proxy.Xcritical = h.critical
	proxy.XjwkSetURL = h.jwkSetURL
	proxy.XkeyID = h.keyID
	proxy.Xtyp = h.typ
	proxy.Xx509CertChain = h.x509CertChain
	proxy.Xx509CertThumbprint = h.x509CertThumbprint
	proxy.Xx509CertThumbprintS256 = h.x509CertThumbprintS256
	proxy.Xx509URL = h.x509URL
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(proxy); err != nil {
		return nil, errors.Wrap(err, `failed to encode proxy to JSON`)
	}
	hasContent := buf.Len() > 3 // encoding/json always adds a newline, so "{}\n" is the empty hash
	if l := len(h.privateParams); l > 0 {
		buf.Truncate(buf.Len() - 2)
		keys := make([]string, 0, l)
		for k := range h.privateParams {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if hasContent || i > 0 {
				fmt.Fprintf(&buf, `,`)
			}
			fmt.Fprintf(&buf, `%s:`, strconv.Quote(k))
			if err := enc.Encode(h.privateParams[k]); err != nil {
				return nil, errors.Wrapf(err, `failed to encode private param %s`, k)
			}
		}
		fmt.Fprintf(&buf, `}`)
	}
	return buf.Bytes(), nil
}
