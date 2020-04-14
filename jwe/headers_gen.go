// This file is auto-generated. DO NOT EDIT
package jwe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/lestrrat-go/jwx/buffer"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

const (
	AgreementPartyUInfoKey    = "apu"
	AgreementPartyVInfoKey    = "apv"
	AlgorithmKey              = "alg"
	CompressionKey            = "zip"
	ContentEncryptionKey      = "enc"
	ContentTypeKey            = "cty"
	CriticalKey               = "crit"
	EphemeralPublicKeyKey     = "epk"
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
	AgreementPartyUInfo() buffer.Buffer
	AgreementPartyVInfo() buffer.Buffer
	Algorithm() jwa.KeyEncryptionAlgorithm
	Compression() jwa.CompressionAlgorithm
	ContentEncryption() jwa.ContentEncryptionAlgorithm
	ContentType() string
	Critical() []string
	EphemeralPublicKey() *jwk.ECDSAPublicKey
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
	agreementPartyUInfo    buffer.Buffer                  `json:"apu,omitempty"`      //
	agreementPartyVInfo    buffer.Buffer                  `json:"apv,omitempty"`      //
	algorithm              jwa.KeyEncryptionAlgorithm     `json:"alg,omitempty"`      //
	compression            jwa.CompressionAlgorithm       `json:"zip,omitempty"`      //
	contentEncryption      jwa.ContentEncryptionAlgorithm `json:"enc,omitempty"`      //
	contentType            string                         `json:"cty,omitempty"`      //
	critical               []string                       `json:"crit,omitempty"`     //
	ephemeralPublicKey     *jwk.ECDSAPublicKey            `json:"epk,omitempty"`      //
	jwk                    jwk.Key                        `json:"jwk,omitempty"`      //
	jwkSetURL              string                         `json:"jku,omitempty"`      //
	keyID                  string                         `json:"kid,omitempty"`      //
	typ                    string                         `json:"typ,omitempty"`      //
	x509CertChain          []string                       `json:"x5c,omitempty"`      //
	x509CertThumbprint     string                         `json:"x5t,omitempty"`      //
	x509CertThumbprintS256 string                         `json:"x5t#S256,omitempty"` //
	x509URL                string                         `json:"x5u,omitempty"`      //
	privateParams          map[string]interface{}
}

type standardHeadersMarshalProxy struct {
	XagreementPartyUInfo    buffer.Buffer                  `json:"apu,omitempty"`
	XagreementPartyVInfo    buffer.Buffer                  `json:"apv,omitempty"`
	Xalgorithm              jwa.KeyEncryptionAlgorithm     `json:"alg,omitempty"`
	Xcompression            jwa.CompressionAlgorithm       `json:"zip,omitempty"`
	XcontentEncryption      jwa.ContentEncryptionAlgorithm `json:"enc,omitempty"`
	XcontentType            string                         `json:"cty,omitempty"`
	Xcritical               []string                       `json:"crit,omitempty"`
	XephemeralPublicKey     *jwk.ECDSAPublicKey            `json:"epk,omitempty"`
	Xjwk                    json.RawMessage                `json:"jwk,omitempty"`
	XjwkSetURL              string                         `json:"jku,omitempty"`
	XkeyID                  string                         `json:"kid,omitempty"`
	Xtyp                    string                         `json:"typ,omitempty"`
	Xx509CertChain          []string                       `json:"x5c,omitempty"`
	Xx509CertThumbprint     string                         `json:"x5t,omitempty"`
	Xx509CertThumbprintS256 string                         `json:"x5t#S256,omitempty"`
	Xx509URL                string                         `json:"x5u,omitempty"`
}

func NewHeaders() Headers {
	return &stdHeaders{}
}

func (h *stdHeaders) AgreementPartyUInfo() buffer.Buffer {
	return h.agreementPartyUInfo
}

func (h *stdHeaders) AgreementPartyVInfo() buffer.Buffer {
	return h.agreementPartyVInfo
}

func (h *stdHeaders) Algorithm() jwa.KeyEncryptionAlgorithm {
	return h.algorithm
}

func (h *stdHeaders) Compression() jwa.CompressionAlgorithm {
	return h.compression
}

func (h *stdHeaders) ContentEncryption() jwa.ContentEncryptionAlgorithm {
	return h.contentEncryption
}

func (h *stdHeaders) ContentType() string {
	return h.contentType
}

func (h *stdHeaders) Critical() []string {
	return h.critical
}

func (h *stdHeaders) EphemeralPublicKey() *jwk.ECDSAPublicKey {
	return h.ephemeralPublicKey
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
	if h.agreementPartyUInfo.Len() > 0 {
		pairs = append(pairs, &HeaderPair{Key: "apu", Value: h.agreementPartyUInfo})
	}
	if h.agreementPartyVInfo.Len() > 0 {
		pairs = append(pairs, &HeaderPair{Key: "apv", Value: h.agreementPartyVInfo})
	}
	if h.algorithm != "" {
		pairs = append(pairs, &HeaderPair{Key: "alg", Value: h.algorithm})
	}
	if h.compression != "" {
		pairs = append(pairs, &HeaderPair{Key: "zip", Value: h.compression})
	}
	if h.contentEncryption != "" {
		pairs = append(pairs, &HeaderPair{Key: "enc", Value: h.contentEncryption})
	}
	if h.contentType != "" {
		pairs = append(pairs, &HeaderPair{Key: "cty", Value: h.contentType})
	}
	if len(h.critical) > 0 {
		pairs = append(pairs, &HeaderPair{Key: "crit", Value: h.critical})
	}
	if h.ephemeralPublicKey != nil {
		pairs = append(pairs, &HeaderPair{Key: "epk", Value: h.ephemeralPublicKey})
	}
	if h.jwk != nil {
		pairs = append(pairs, &HeaderPair{Key: "jwk", Value: h.jwk})
	}
	if h.jwkSetURL != "" {
		pairs = append(pairs, &HeaderPair{Key: "jku", Value: h.jwkSetURL})
	}
	if h.keyID != "" {
		pairs = append(pairs, &HeaderPair{Key: "kid", Value: h.keyID})
	}
	if h.typ != "" {
		pairs = append(pairs, &HeaderPair{Key: "typ", Value: h.typ})
	}
	if len(h.x509CertChain) > 0 {
		pairs = append(pairs, &HeaderPair{Key: "x5c", Value: h.x509CertChain})
	}
	if h.x509CertThumbprint != "" {
		pairs = append(pairs, &HeaderPair{Key: "x5t", Value: h.x509CertThumbprint})
	}
	if h.x509CertThumbprintS256 != "" {
		pairs = append(pairs, &HeaderPair{Key: "x5t#S256", Value: h.x509CertThumbprintS256})
	}
	if h.x509URL != "" {
		pairs = append(pairs, &HeaderPair{Key: "x5u", Value: h.x509URL})
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
	case AgreementPartyUInfoKey:
		v := h.agreementPartyUInfo
		if v == nil {
			return nil, false
		}
		return v, true
	case AgreementPartyVInfoKey:
		v := h.agreementPartyVInfo
		if v == nil {
			return nil, false
		}
		return v, true
	case AlgorithmKey:
		v := h.algorithm
		if v == "" {
			return nil, false
		}
		return v, true
	case CompressionKey:
		v := h.compression
		if v == "" {
			return nil, false
		}
		return v, true
	case ContentEncryptionKey:
		v := h.contentEncryption
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
	case EphemeralPublicKeyKey:
		v := h.ephemeralPublicKey
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
	case AgreementPartyUInfoKey:
		if err := h.agreementPartyUInfo.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, AgreementPartyUInfoKey)
		}
		return nil
	case AgreementPartyVInfoKey:
		if err := h.agreementPartyVInfo.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, AgreementPartyVInfoKey)
		}
		return nil
	case AlgorithmKey:
		if v, ok := value.(jwa.KeyEncryptionAlgorithm); ok {
			h.algorithm = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, AlgorithmKey, value)
	case CompressionKey:
		if v, ok := value.(jwa.CompressionAlgorithm); ok {
			h.compression = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, CompressionKey, value)
	case ContentEncryptionKey:
		if v, ok := value.(jwa.ContentEncryptionAlgorithm); ok {
			h.contentEncryption = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ContentEncryptionKey, value)
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
	case EphemeralPublicKeyKey:
		if v, ok := value.(*jwk.ECDSAPublicKey); ok {
			h.ephemeralPublicKey = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, EphemeralPublicKeyKey, value)
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
	h.agreementPartyUInfo = proxy.XagreementPartyUInfo
	h.agreementPartyVInfo = proxy.XagreementPartyVInfo
	h.algorithm = proxy.Xalgorithm
	h.compression = proxy.Xcompression
	h.contentEncryption = proxy.XcontentEncryption
	h.contentType = proxy.XcontentType
	h.critical = proxy.Xcritical
	h.ephemeralPublicKey = proxy.XephemeralPublicKey
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
	delete(m, AgreementPartyUInfoKey)
	delete(m, AgreementPartyVInfoKey)
	delete(m, AlgorithmKey)
	delete(m, CompressionKey)
	delete(m, ContentEncryptionKey)
	delete(m, ContentTypeKey)
	delete(m, CriticalKey)
	delete(m, EphemeralPublicKeyKey)
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
	proxy.XagreementPartyUInfo = h.agreementPartyUInfo
	proxy.XagreementPartyVInfo = h.agreementPartyVInfo
	proxy.Xalgorithm = h.algorithm
	proxy.Xcompression = h.compression
	proxy.XcontentEncryption = h.contentEncryption
	proxy.XcontentType = h.contentType
	proxy.Xcritical = h.critical
	proxy.XephemeralPublicKey = h.ephemeralPublicKey
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
	if l := len(h.privateParams); l > 0 {
		buf.Truncate(buf.Len() - 2)
		keys := make([]string, 0, l)
		for k := range h.privateParams {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
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
