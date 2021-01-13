// This file is auto-generated. DO NOT EDIT

package jwk

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"sort"
	"strconv"

	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/internal/iter"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

const (
	OKPCrvKey = "crv"
	OKPDKey   = "d"
	OKPXKey   = "x"
)

type OKPPrivateKey interface {
	Key
	FromRaw(interface{}) error
	Crv() jwa.EllipticCurveAlgorithm
	D() []byte
	X() []byte
	PublicKey() (OKPPublicKey, error)
}

type okpPrivateKey struct {
	algorithm              *string // https://tools.ietf.org/html/rfc7517#section-4.4
	crv                    *jwa.EllipticCurveAlgorithm
	d                      []byte
	keyID                  *string           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyUsage               *string           // https://tools.ietf.org/html/rfc7517#section-4.2
	keyops                 *KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	x                      []byte
	x509CertChain          *CertificateChain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string           // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string           // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string           // https://tools.ietf.org/html/rfc7515#section-4.1.5
	privateParams          map[string]interface{}
}

type okpPrivateKeyMarshalProxy struct {
	XkeyType                jwa.KeyType                 `json:"kty"`
	Xalgorithm              *string                     `json:"alg,omitempty"`
	Xcrv                    *jwa.EllipticCurveAlgorithm `json:"crv,omitempty"`
	Xd                      *string                     `json:"d,omitempty"`
	XkeyID                  *string                     `json:"kid,omitempty"`
	XkeyUsage               *string                     `json:"use,omitempty"`
	Xkeyops                 *KeyOperationList           `json:"key_ops,omitempty"`
	Xx                      *string                     `json:"x,omitempty"`
	Xx509CertChain          *CertificateChain           `json:"x5c,omitempty"`
	Xx509CertThumbprint     *string                     `json:"x5t,omitempty"`
	Xx509CertThumbprintS256 *string                     `json:"x5t#S256,omitempty"`
	Xx509URL                *string                     `json:"x5u,omitempty"`
}

func (h okpPrivateKey) KeyType() jwa.KeyType {
	return jwa.OKP
}

func (h *okpPrivateKey) Algorithm() string {
	if h.algorithm != nil {
		return *(h.algorithm)
	}
	return ""
}

func (h *okpPrivateKey) Crv() jwa.EllipticCurveAlgorithm {
	if h.crv != nil {
		return *(h.crv)
	}
	return jwa.InvalidEllipticCurve
}

func (h *okpPrivateKey) D() []byte {
	return h.d
}

func (h *okpPrivateKey) KeyID() string {
	if h.keyID != nil {
		return *(h.keyID)
	}
	return ""
}

func (h *okpPrivateKey) KeyUsage() string {
	if h.keyUsage != nil {
		return *(h.keyUsage)
	}
	return ""
}

func (h *okpPrivateKey) KeyOps() KeyOperationList {
	if h.keyops != nil {
		return *(h.keyops)
	}
	return nil
}

func (h *okpPrivateKey) X() []byte {
	return h.x
}

func (h *okpPrivateKey) X509CertChain() []*x509.Certificate {
	if h.x509CertChain != nil {
		return h.x509CertChain.Get()
	}
	return nil
}

func (h *okpPrivateKey) X509CertThumbprint() string {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint)
	}
	return ""
}

func (h *okpPrivateKey) X509CertThumbprintS256() string {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256)
	}
	return ""
}

func (h *okpPrivateKey) X509URL() string {
	if h.x509URL != nil {
		return *(h.x509URL)
	}
	return ""
}

func (h *okpPrivateKey) iterate(ctx context.Context, ch chan *HeaderPair) {
	defer close(ch)

	var pairs []*HeaderPair
	pairs = append(pairs, &HeaderPair{Key: "kty", Value: jwa.OKP})
	if h.algorithm != nil {
		pairs = append(pairs, &HeaderPair{Key: AlgorithmKey, Value: *(h.algorithm)})
	}
	if h.crv != nil {
		pairs = append(pairs, &HeaderPair{Key: OKPCrvKey, Value: *(h.crv)})
	}
	if h.d != nil {
		pairs = append(pairs, &HeaderPair{Key: OKPDKey, Value: h.d})
	}
	if h.keyID != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyIDKey, Value: *(h.keyID)})
	}
	if h.keyUsage != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyUsageKey, Value: *(h.keyUsage)})
	}
	if h.keyops != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyOpsKey, Value: *(h.keyops)})
	}
	if h.x != nil {
		pairs = append(pairs, &HeaderPair{Key: OKPXKey, Value: h.x})
	}
	if h.x509CertChain != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertChainKey, Value: *(h.x509CertChain)})
	}
	if h.x509CertThumbprint != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertThumbprintKey, Value: *(h.x509CertThumbprint)})
	}
	if h.x509CertThumbprintS256 != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertThumbprintS256Key, Value: *(h.x509CertThumbprintS256)})
	}
	if h.x509URL != nil {
		pairs = append(pairs, &HeaderPair{Key: X509URLKey, Value: *(h.x509URL)})
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

func (h *okpPrivateKey) PrivateParams() map[string]interface{} {
	return h.privateParams
}

func (h *okpPrivateKey) Get(name string) (interface{}, bool) {
	switch name {
	case KeyTypeKey:
		return h.KeyType(), true
	case AlgorithmKey:
		if h.algorithm == nil {
			return nil, false
		}
		return *(h.algorithm), true
	case OKPCrvKey:
		if h.crv == nil {
			return nil, false
		}
		return *(h.crv), true
	case OKPDKey:
		if h.d == nil {
			return nil, false
		}
		return h.d, true
	case KeyIDKey:
		if h.keyID == nil {
			return nil, false
		}
		return *(h.keyID), true
	case KeyUsageKey:
		if h.keyUsage == nil {
			return nil, false
		}
		return *(h.keyUsage), true
	case KeyOpsKey:
		if h.keyops == nil {
			return nil, false
		}
		return *(h.keyops), true
	case OKPXKey:
		if h.x == nil {
			return nil, false
		}
		return h.x, true
	case X509CertChainKey:
		if h.x509CertChain == nil {
			return nil, false
		}
		return *(h.x509CertChain), true
	case X509CertThumbprintKey:
		if h.x509CertThumbprint == nil {
			return nil, false
		}
		return *(h.x509CertThumbprint), true
	case X509CertThumbprintS256Key:
		if h.x509CertThumbprintS256 == nil {
			return nil, false
		}
		return *(h.x509CertThumbprintS256), true
	case X509URLKey:
		if h.x509URL == nil {
			return nil, false
		}
		return *(h.x509URL), true
	default:
		v, ok := h.privateParams[name]
		return v, ok
	}
}

func (h *okpPrivateKey) Set(name string, value interface{}) error {
	switch name {
	case "kty":
		return nil
	case AlgorithmKey:
		switch v := value.(type) {
		case string:
			h.algorithm = &v
		case fmt.Stringer:
			tmp := v.String()
			h.algorithm = &tmp
		default:
			return errors.Errorf(`invalid type for %s key: %T`, AlgorithmKey, value)
		}
		return nil
	case OKPCrvKey:
		if v, ok := value.(jwa.EllipticCurveAlgorithm); ok {
			h.crv = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, OKPCrvKey, value)
	case OKPDKey:
		if v, ok := value.([]byte); ok {
			h.d = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, OKPDKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case KeyUsageKey:
		switch v := value.(type) {
		case KeyUsageType:
			switch v {
			case ForSignature, ForEncryption:
				tmp := v.String()
				h.keyUsage = &tmp
			default:
				return errors.Errorf(`invalid key usage type %s`, v)
			}
		case string:
			h.keyUsage = &v
		default:
			return errors.Errorf(`invalid key usage type %s`, v)
		}
	case KeyOpsKey:
		var acceptor KeyOperationList
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, KeyOpsKey)
		}
		h.keyops = &acceptor
		return nil
	case OKPXKey:
		if v, ok := value.([]byte); ok {
			h.x = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, OKPXKey, value)
	case X509CertChainKey:
		var acceptor CertificateChain
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, X509CertChainKey)
		}
		h.x509CertChain = &acceptor
		return nil
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

func (h *okpPrivateKey) UnmarshalJSON(buf []byte) error {
	var proxy okpPrivateKeyMarshalProxy
	if err := json.Unmarshal(buf, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmarshal okpPrivateKey`)
	}
	if proxy.XkeyType != jwa.OKP {
		return errors.Errorf(`invalid kty value for OKPPrivateKey (%s)`, proxy.XkeyType)
	}
	h.algorithm = proxy.Xalgorithm
	h.crv = proxy.Xcrv
	if proxy.Xd == nil {
		return errors.New(`required field d is missing`)
	}
	if h.d = nil; proxy.Xd != nil {
		decoded, err := base64.DecodeString(*(proxy.Xd))
		if err != nil {
			return errors.Wrap(err, `failed to decode base64 value for d`)
		}
		h.d = decoded
	}
	h.keyID = proxy.XkeyID
	h.keyUsage = proxy.XkeyUsage
	h.keyops = proxy.Xkeyops
	if proxy.Xx == nil {
		return errors.New(`required field x is missing`)
	}
	if h.x = nil; proxy.Xx != nil {
		decoded, err := base64.DecodeString(*(proxy.Xx))
		if err != nil {
			return errors.Wrap(err, `failed to decode base64 value for x`)
		}
		h.x = decoded
	}
	h.x509CertChain = proxy.Xx509CertChain
	h.x509CertThumbprint = proxy.Xx509CertThumbprint
	h.x509CertThumbprintS256 = proxy.Xx509CertThumbprintS256
	h.x509URL = proxy.Xx509URL
	var m map[string]interface{}
	if err := json.Unmarshal(buf, &m); err != nil {
		return errors.Wrap(err, `failed to parse privsate parameters`)
	}
	delete(m, `kty`)
	delete(m, AlgorithmKey)
	delete(m, OKPCrvKey)
	delete(m, OKPDKey)
	delete(m, KeyIDKey)
	delete(m, KeyUsageKey)
	delete(m, KeyOpsKey)
	delete(m, OKPXKey)
	delete(m, X509CertChainKey)
	delete(m, X509CertThumbprintKey)
	delete(m, X509CertThumbprintS256Key)
	delete(m, X509URLKey)
	h.privateParams = m
	return nil
}

func (h okpPrivateKey) MarshalJSON() ([]byte, error) {
	var proxy okpPrivateKeyMarshalProxy
	proxy.XkeyType = jwa.OKP
	proxy.Xalgorithm = h.algorithm
	proxy.Xcrv = h.crv
	if len(h.d) > 0 {
		v := base64.EncodeToString(h.d)
		proxy.Xd = &v
	}
	proxy.XkeyID = h.keyID
	proxy.XkeyUsage = h.keyUsage
	proxy.Xkeyops = h.keyops
	if len(h.x) > 0 {
		v := base64.EncodeToString(h.x)
		proxy.Xx = &v
	}
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
	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		return nil, errors.Wrap(err, `failed to do second pass unmarshal during MarshalJSON`)
	}
	return json.Marshal(m)
}

func (h *okpPrivateKey) Iterate(ctx context.Context) HeaderIterator {
	ch := make(chan *HeaderPair)
	go h.iterate(ctx, ch)
	return mapiter.New(ch)
}

func (h *okpPrivateKey) Walk(ctx context.Context, visitor HeaderVisitor) error {
	return iter.WalkMap(ctx, h, visitor)
}

func (h *okpPrivateKey) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return iter.AsMap(ctx, h)
}

type OKPPublicKey interface {
	Key
	FromRaw(interface{}) error
	Crv() jwa.EllipticCurveAlgorithm
	X() []byte
}

type okpPublicKey struct {
	algorithm              *string // https://tools.ietf.org/html/rfc7517#section-4.4
	crv                    *jwa.EllipticCurveAlgorithm
	keyID                  *string           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyUsage               *string           // https://tools.ietf.org/html/rfc7517#section-4.2
	keyops                 *KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	x                      []byte
	x509CertChain          *CertificateChain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string           // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string           // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string           // https://tools.ietf.org/html/rfc7515#section-4.1.5
	privateParams          map[string]interface{}
}

type okpPublicKeyMarshalProxy struct {
	XkeyType                jwa.KeyType                 `json:"kty"`
	Xalgorithm              *string                     `json:"alg,omitempty"`
	Xcrv                    *jwa.EllipticCurveAlgorithm `json:"crv,omitempty"`
	XkeyID                  *string                     `json:"kid,omitempty"`
	XkeyUsage               *string                     `json:"use,omitempty"`
	Xkeyops                 *KeyOperationList           `json:"key_ops,omitempty"`
	Xx                      *string                     `json:"x,omitempty"`
	Xx509CertChain          *CertificateChain           `json:"x5c,omitempty"`
	Xx509CertThumbprint     *string                     `json:"x5t,omitempty"`
	Xx509CertThumbprintS256 *string                     `json:"x5t#S256,omitempty"`
	Xx509URL                *string                     `json:"x5u,omitempty"`
}

func (h okpPublicKey) KeyType() jwa.KeyType {
	return jwa.OKP
}

func (h *okpPublicKey) Algorithm() string {
	if h.algorithm != nil {
		return *(h.algorithm)
	}
	return ""
}

func (h *okpPublicKey) Crv() jwa.EllipticCurveAlgorithm {
	if h.crv != nil {
		return *(h.crv)
	}
	return jwa.InvalidEllipticCurve
}

func (h *okpPublicKey) KeyID() string {
	if h.keyID != nil {
		return *(h.keyID)
	}
	return ""
}

func (h *okpPublicKey) KeyUsage() string {
	if h.keyUsage != nil {
		return *(h.keyUsage)
	}
	return ""
}

func (h *okpPublicKey) KeyOps() KeyOperationList {
	if h.keyops != nil {
		return *(h.keyops)
	}
	return nil
}

func (h *okpPublicKey) X() []byte {
	return h.x
}

func (h *okpPublicKey) X509CertChain() []*x509.Certificate {
	if h.x509CertChain != nil {
		return h.x509CertChain.Get()
	}
	return nil
}

func (h *okpPublicKey) X509CertThumbprint() string {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint)
	}
	return ""
}

func (h *okpPublicKey) X509CertThumbprintS256() string {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256)
	}
	return ""
}

func (h *okpPublicKey) X509URL() string {
	if h.x509URL != nil {
		return *(h.x509URL)
	}
	return ""
}

func (h *okpPublicKey) iterate(ctx context.Context, ch chan *HeaderPair) {
	defer close(ch)

	var pairs []*HeaderPair
	pairs = append(pairs, &HeaderPair{Key: "kty", Value: jwa.OKP})
	if h.algorithm != nil {
		pairs = append(pairs, &HeaderPair{Key: AlgorithmKey, Value: *(h.algorithm)})
	}
	if h.crv != nil {
		pairs = append(pairs, &HeaderPair{Key: OKPCrvKey, Value: *(h.crv)})
	}
	if h.keyID != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyIDKey, Value: *(h.keyID)})
	}
	if h.keyUsage != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyUsageKey, Value: *(h.keyUsage)})
	}
	if h.keyops != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyOpsKey, Value: *(h.keyops)})
	}
	if h.x != nil {
		pairs = append(pairs, &HeaderPair{Key: OKPXKey, Value: h.x})
	}
	if h.x509CertChain != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertChainKey, Value: *(h.x509CertChain)})
	}
	if h.x509CertThumbprint != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertThumbprintKey, Value: *(h.x509CertThumbprint)})
	}
	if h.x509CertThumbprintS256 != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertThumbprintS256Key, Value: *(h.x509CertThumbprintS256)})
	}
	if h.x509URL != nil {
		pairs = append(pairs, &HeaderPair{Key: X509URLKey, Value: *(h.x509URL)})
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

func (h *okpPublicKey) PrivateParams() map[string]interface{} {
	return h.privateParams
}

func (h *okpPublicKey) Get(name string) (interface{}, bool) {
	switch name {
	case KeyTypeKey:
		return h.KeyType(), true
	case AlgorithmKey:
		if h.algorithm == nil {
			return nil, false
		}
		return *(h.algorithm), true
	case OKPCrvKey:
		if h.crv == nil {
			return nil, false
		}
		return *(h.crv), true
	case KeyIDKey:
		if h.keyID == nil {
			return nil, false
		}
		return *(h.keyID), true
	case KeyUsageKey:
		if h.keyUsage == nil {
			return nil, false
		}
		return *(h.keyUsage), true
	case KeyOpsKey:
		if h.keyops == nil {
			return nil, false
		}
		return *(h.keyops), true
	case OKPXKey:
		if h.x == nil {
			return nil, false
		}
		return h.x, true
	case X509CertChainKey:
		if h.x509CertChain == nil {
			return nil, false
		}
		return *(h.x509CertChain), true
	case X509CertThumbprintKey:
		if h.x509CertThumbprint == nil {
			return nil, false
		}
		return *(h.x509CertThumbprint), true
	case X509CertThumbprintS256Key:
		if h.x509CertThumbprintS256 == nil {
			return nil, false
		}
		return *(h.x509CertThumbprintS256), true
	case X509URLKey:
		if h.x509URL == nil {
			return nil, false
		}
		return *(h.x509URL), true
	default:
		v, ok := h.privateParams[name]
		return v, ok
	}
}

func (h *okpPublicKey) Set(name string, value interface{}) error {
	switch name {
	case "kty":
		return nil
	case AlgorithmKey:
		switch v := value.(type) {
		case string:
			h.algorithm = &v
		case fmt.Stringer:
			tmp := v.String()
			h.algorithm = &tmp
		default:
			return errors.Errorf(`invalid type for %s key: %T`, AlgorithmKey, value)
		}
		return nil
	case OKPCrvKey:
		if v, ok := value.(jwa.EllipticCurveAlgorithm); ok {
			h.crv = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, OKPCrvKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case KeyUsageKey:
		switch v := value.(type) {
		case KeyUsageType:
			switch v {
			case ForSignature, ForEncryption:
				tmp := v.String()
				h.keyUsage = &tmp
			default:
				return errors.Errorf(`invalid key usage type %s`, v)
			}
		case string:
			h.keyUsage = &v
		default:
			return errors.Errorf(`invalid key usage type %s`, v)
		}
	case KeyOpsKey:
		var acceptor KeyOperationList
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, KeyOpsKey)
		}
		h.keyops = &acceptor
		return nil
	case OKPXKey:
		if v, ok := value.([]byte); ok {
			h.x = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, OKPXKey, value)
	case X509CertChainKey:
		var acceptor CertificateChain
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, X509CertChainKey)
		}
		h.x509CertChain = &acceptor
		return nil
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

func (h *okpPublicKey) UnmarshalJSON(buf []byte) error {
	var proxy okpPublicKeyMarshalProxy
	if err := json.Unmarshal(buf, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmarshal okpPublicKey`)
	}
	if proxy.XkeyType != jwa.OKP {
		return errors.Errorf(`invalid kty value for OKPPublicKey (%s)`, proxy.XkeyType)
	}
	h.algorithm = proxy.Xalgorithm
	h.crv = proxy.Xcrv
	h.keyID = proxy.XkeyID
	h.keyUsage = proxy.XkeyUsage
	h.keyops = proxy.Xkeyops
	if proxy.Xx == nil {
		return errors.New(`required field x is missing`)
	}
	if h.x = nil; proxy.Xx != nil {
		decoded, err := base64.DecodeString(*(proxy.Xx))
		if err != nil {
			return errors.Wrap(err, `failed to decode base64 value for x`)
		}
		h.x = decoded
	}
	h.x509CertChain = proxy.Xx509CertChain
	h.x509CertThumbprint = proxy.Xx509CertThumbprint
	h.x509CertThumbprintS256 = proxy.Xx509CertThumbprintS256
	h.x509URL = proxy.Xx509URL
	var m map[string]interface{}
	if err := json.Unmarshal(buf, &m); err != nil {
		return errors.Wrap(err, `failed to parse privsate parameters`)
	}
	delete(m, `kty`)
	delete(m, AlgorithmKey)
	delete(m, OKPCrvKey)
	delete(m, KeyIDKey)
	delete(m, KeyUsageKey)
	delete(m, KeyOpsKey)
	delete(m, OKPXKey)
	delete(m, X509CertChainKey)
	delete(m, X509CertThumbprintKey)
	delete(m, X509CertThumbprintS256Key)
	delete(m, X509URLKey)
	h.privateParams = m
	return nil
}

func (h okpPublicKey) MarshalJSON() ([]byte, error) {
	var proxy okpPublicKeyMarshalProxy
	proxy.XkeyType = jwa.OKP
	proxy.Xalgorithm = h.algorithm
	proxy.Xcrv = h.crv
	proxy.XkeyID = h.keyID
	proxy.XkeyUsage = h.keyUsage
	proxy.Xkeyops = h.keyops
	if len(h.x) > 0 {
		v := base64.EncodeToString(h.x)
		proxy.Xx = &v
	}
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
	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		return nil, errors.Wrap(err, `failed to do second pass unmarshal during MarshalJSON`)
	}
	return json.Marshal(m)
}

func (h *okpPublicKey) Iterate(ctx context.Context) HeaderIterator {
	ch := make(chan *HeaderPair)
	go h.iterate(ctx, ch)
	return mapiter.New(ch)
}

func (h *okpPublicKey) Walk(ctx context.Context, visitor HeaderVisitor) error {
	return iter.WalkMap(ctx, h, visitor)
}

func (h *okpPublicKey) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return iter.AsMap(ctx, h)
}
