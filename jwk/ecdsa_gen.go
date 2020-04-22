// This file is auto-generated. DO NOT EDIT

package jwk

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/internal/iter"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

const (
	ecdsaCrvKey = "crv"
	ecdsaDKey   = "d"
	ecdsaXKey   = "x"
	ecdsaYKey   = "y"
)

type ECDSAPrivateKey struct {
	algorithm              *string // https://tools.ietf.org/html/rfc7517#section-4.4
	crv                    *jwa.EllipticCurveAlgorithm
	d                      []byte
	keyID                  *string          // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyType                *jwa.KeyType     // https://tools.ietf.org/html/rfc7517#section-4.1
	keyUsage               *string          // https://tools.ietf.org/html/rfc7517#section-4.2
	keyops                 KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	x                      []byte
	x509CertChain          *CertificateChain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string           // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string           // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string           // https://tools.ietf.org/html/rfc7515#section-4.1.5
	y                      []byte
	privateParams          map[string]interface{}
}

type ecdsaPrivateKeyMarshalProxy struct {
	Xalgorithm              *string                     `json:"alg,omitempty"`
	Xcrv                    *jwa.EllipticCurveAlgorithm `json:"crv,omitempty"`
	Xd                      *string                     `json:"d,omitempty"`
	XkeyID                  *string                     `json:"kid,omitempty"`
	XkeyType                *jwa.KeyType                `json:"kty,omitempty"`
	XkeyUsage               *string                     `json:"use,omitempty"`
	Xkeyops                 KeyOperationList            `json:"key_ops,omitempty"`
	Xx                      *string                     `json:"x,omitempty"`
	Xx509CertChain          *CertificateChain           `json:"x5c,omitempty"`
	Xx509CertThumbprint     *string                     `json:"x5t,omitempty"`
	Xx509CertThumbprintS256 *string                     `json:"x5t#S256,omitempty"`
	Xx509URL                *string                     `json:"x5u,omitempty"`
	Xy                      *string                     `json:"y,omitempty"`
}

func (h *ECDSAPrivateKey) Algorithm() string {
	if h.algorithm != nil {
		return *(h.algorithm)
	}
	return ""
}

func (h *ECDSAPrivateKey) Crv() jwa.EllipticCurveAlgorithm {
	if h.crv != nil {
		return *(h.crv)
	}
	return jwa.InvalidEllipticCurve
}

func (h *ECDSAPrivateKey) D() []byte {
	return h.d
}

func (h *ECDSAPrivateKey) KeyID() string {
	if h.keyID != nil {
		return *(h.keyID)
	}
	return ""
}

func (h *ECDSAPrivateKey) KeyType() jwa.KeyType {
	if h.keyType != nil {
		return *(h.keyType)
	}
	return jwa.InvalidKeyType
}

func (h *ECDSAPrivateKey) KeyUsage() string {
	if h.keyUsage != nil {
		return *(h.keyUsage)
	}
	return ""
}

func (h *ECDSAPrivateKey) KeyOps() KeyOperationList {
	return h.keyops
}

func (h *ECDSAPrivateKey) X() []byte {
	return h.x
}

func (h *ECDSAPrivateKey) X509CertChain() []*x509.Certificate {
	if h.x509CertChain != nil {
		return h.x509CertChain.Get()
	}
	return nil
}

func (h *ECDSAPrivateKey) X509CertThumbprint() string {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint)
	}
	return ""
}

func (h *ECDSAPrivateKey) X509CertThumbprintS256() string {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256)
	}
	return ""
}

func (h *ECDSAPrivateKey) X509URL() string {
	if h.x509URL != nil {
		return *(h.x509URL)
	}
	return ""
}

func (h *ECDSAPrivateKey) Y() []byte {
	return h.y
}

func (h *ECDSAPrivateKey) iterate(ctx context.Context, ch chan *HeaderPair) {
	defer close(ch)
	var pairs []*HeaderPair
	if h.algorithm != nil {
		pairs = append(pairs, &HeaderPair{Key: AlgorithmKey, Value: *(h.algorithm)})
	}
	if h.crv != nil {
		pairs = append(pairs, &HeaderPair{Key: ecdsaCrvKey, Value: *(h.crv)})
	}
	if h.d != nil {
		pairs = append(pairs, &HeaderPair{Key: ecdsaDKey, Value: h.d})
	}
	if h.keyID != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyIDKey, Value: *(h.keyID)})
	}
	if h.keyType != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyTypeKey, Value: *(h.keyType)})
	}
	if h.keyUsage != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyUsageKey, Value: *(h.keyUsage)})
	}
	if h.keyops != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyOpsKey, Value: h.keyops})
	}
	if h.x != nil {
		pairs = append(pairs, &HeaderPair{Key: ecdsaXKey, Value: h.x})
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
	if h.y != nil {
		pairs = append(pairs, &HeaderPair{Key: ecdsaYKey, Value: h.y})
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

func (h *ECDSAPrivateKey) PrivateParams() map[string]interface{} {
	return h.privateParams
}

func (h *ECDSAPrivateKey) Get(name string) (interface{}, bool) {
	switch name {
	case AlgorithmKey:
		if h.algorithm == nil {
			return nil, false
		}
		return *(h.algorithm), true
	case ecdsaCrvKey:
		if h.crv == nil {
			return nil, false
		}
		return *(h.crv), true
	case ecdsaDKey:
		if h.d == nil {
			return nil, false
		}
		return h.d, true
	case KeyIDKey:
		if h.keyID == nil {
			return nil, false
		}
		return *(h.keyID), true
	case KeyTypeKey:
		if h.keyType == nil {
			return nil, false
		}
		return *(h.keyType), true
	case KeyUsageKey:
		if h.keyUsage == nil {
			return nil, false
		}
		return *(h.keyUsage), true
	case KeyOpsKey:
		if h.keyops == nil {
			return nil, false
		}
		return h.keyops, true
	case ecdsaXKey:
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
	case ecdsaYKey:
		if h.y == nil {
			return nil, false
		}
		return h.y, true
	default:
		v, ok := h.privateParams[name]
		return v, ok
	}
}

func (h *ECDSAPrivateKey) Set(name string, value interface{}) error {
	switch name {
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
	case ecdsaCrvKey:
		if v, ok := value.(jwa.EllipticCurveAlgorithm); ok {
			h.crv = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ecdsaCrvKey, value)
	case ecdsaDKey:
		if v, ok := value.([]byte); ok {
			h.d = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ecdsaDKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case KeyTypeKey:
		var acceptor jwa.KeyType
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, KeyTypeKey)
		}
		h.keyType = &acceptor
		return nil
	case KeyUsageKey:
		if v, ok := value.(string); ok {
			h.keyUsage = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyUsageKey, value)
	case KeyOpsKey:
		var acceptor KeyOperationList
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, KeyOpsKey)
		}
		h.keyops = acceptor
		return nil
	case ecdsaXKey:
		if v, ok := value.([]byte); ok {
			h.x = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ecdsaXKey, value)
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
	case ecdsaYKey:
		if v, ok := value.([]byte); ok {
			h.y = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ecdsaYKey, value)
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

func (h *ECDSAPrivateKey) UnmarshalJSON(buf []byte) error {
	var proxy ecdsaPrivateKeyMarshalProxy
	if err := json.Unmarshal(buf, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmarshal ECDSAPrivateKey`)
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
	h.keyType = proxy.XkeyType
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
	if proxy.Xy == nil {
		return errors.New(`required field y is missing`)
	}
	if h.y = nil; proxy.Xy != nil {
		decoded, err := base64.DecodeString(*(proxy.Xy))
		if err != nil {
			return errors.Wrap(err, `failed to decode base64 value for y`)
		}
		h.y = decoded
	}
	var m map[string]interface{}
	if err := json.Unmarshal(buf, &m); err != nil {
		return errors.Wrap(err, `failed to parse privsate parameters`)
	}
	delete(m, AlgorithmKey)
	delete(m, ecdsaCrvKey)
	delete(m, ecdsaDKey)
	delete(m, KeyIDKey)
	delete(m, KeyTypeKey)
	delete(m, KeyUsageKey)
	delete(m, KeyOpsKey)
	delete(m, ecdsaXKey)
	delete(m, X509CertChainKey)
	delete(m, X509CertThumbprintKey)
	delete(m, X509CertThumbprintS256Key)
	delete(m, X509URLKey)
	delete(m, ecdsaYKey)
	h.privateParams = m
	return nil
}

func (h ECDSAPrivateKey) MarshalJSON() ([]byte, error) {
	var proxy ecdsaPrivateKeyMarshalProxy
	proxy.Xalgorithm = h.algorithm
	proxy.Xcrv = h.crv
	if len(h.d) > 0 {
		v := base64.EncodeToStringStd(h.d)
		proxy.Xd = &v
	}
	proxy.XkeyID = h.keyID
	proxy.XkeyType = h.keyType
	if proxy.XkeyType == nil {
		v := jwa.EC
		proxy.XkeyType = &v
	}
	proxy.XkeyUsage = h.keyUsage
	proxy.Xkeyops = h.keyops
	if len(h.x) > 0 {
		v := base64.EncodeToStringStd(h.x)
		proxy.Xx = &v
	}
	proxy.Xx509CertChain = h.x509CertChain
	proxy.Xx509CertThumbprint = h.x509CertThumbprint
	proxy.Xx509CertThumbprintS256 = h.x509CertThumbprintS256
	proxy.Xx509URL = h.x509URL
	if len(h.y) > 0 {
		v := base64.EncodeToStringStd(h.y)
		proxy.Xy = &v
	}
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

func (h *ECDSAPrivateKey) Iterate(ctx context.Context) HeaderIterator {
	ch := make(chan *HeaderPair)
	go h.iterate(ctx, ch)
	return mapiter.New(ch)
}

func (h *ECDSAPrivateKey) Walk(ctx context.Context, visitor HeaderVisitor) error {
	return iter.WalkMap(ctx, h, visitor)
}

func (h *ECDSAPrivateKey) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return iter.AsMap(ctx, h)
}

type ECDSAPublicKey struct {
	algorithm              *string // https://tools.ietf.org/html/rfc7517#section-4.4
	crv                    *jwa.EllipticCurveAlgorithm
	keyID                  *string          // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyType                *jwa.KeyType     // https://tools.ietf.org/html/rfc7517#section-4.1
	keyUsage               *string          // https://tools.ietf.org/html/rfc7517#section-4.2
	keyops                 KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	x                      []byte
	x509CertChain          *CertificateChain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string           // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string           // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string           // https://tools.ietf.org/html/rfc7515#section-4.1.5
	y                      []byte
	privateParams          map[string]interface{}
}

type ecdsaPublicKeyMarshalProxy struct {
	Xalgorithm              *string                     `json:"alg,omitempty"`
	Xcrv                    *jwa.EllipticCurveAlgorithm `json:"crv,omitempty"`
	XkeyID                  *string                     `json:"kid,omitempty"`
	XkeyType                *jwa.KeyType                `json:"kty,omitempty"`
	XkeyUsage               *string                     `json:"use,omitempty"`
	Xkeyops                 KeyOperationList            `json:"key_ops,omitempty"`
	Xx                      *string                     `json:"x,omitempty"`
	Xx509CertChain          *CertificateChain           `json:"x5c,omitempty"`
	Xx509CertThumbprint     *string                     `json:"x5t,omitempty"`
	Xx509CertThumbprintS256 *string                     `json:"x5t#S256,omitempty"`
	Xx509URL                *string                     `json:"x5u,omitempty"`
	Xy                      *string                     `json:"y,omitempty"`
}

func (h *ECDSAPublicKey) Algorithm() string {
	if h.algorithm != nil {
		return *(h.algorithm)
	}
	return ""
}

func (h *ECDSAPublicKey) Crv() jwa.EllipticCurveAlgorithm {
	if h.crv != nil {
		return *(h.crv)
	}
	return jwa.InvalidEllipticCurve
}

func (h *ECDSAPublicKey) KeyID() string {
	if h.keyID != nil {
		return *(h.keyID)
	}
	return ""
}

func (h *ECDSAPublicKey) KeyType() jwa.KeyType {
	if h.keyType != nil {
		return *(h.keyType)
	}
	return jwa.InvalidKeyType
}

func (h *ECDSAPublicKey) KeyUsage() string {
	if h.keyUsage != nil {
		return *(h.keyUsage)
	}
	return ""
}

func (h *ECDSAPublicKey) KeyOps() KeyOperationList {
	return h.keyops
}

func (h *ECDSAPublicKey) X() []byte {
	return h.x
}

func (h *ECDSAPublicKey) X509CertChain() []*x509.Certificate {
	if h.x509CertChain != nil {
		return h.x509CertChain.Get()
	}
	return nil
}

func (h *ECDSAPublicKey) X509CertThumbprint() string {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint)
	}
	return ""
}

func (h *ECDSAPublicKey) X509CertThumbprintS256() string {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256)
	}
	return ""
}

func (h *ECDSAPublicKey) X509URL() string {
	if h.x509URL != nil {
		return *(h.x509URL)
	}
	return ""
}

func (h *ECDSAPublicKey) Y() []byte {
	return h.y
}

func (h *ECDSAPublicKey) iterate(ctx context.Context, ch chan *HeaderPair) {
	defer close(ch)
	var pairs []*HeaderPair
	if h.algorithm != nil {
		pairs = append(pairs, &HeaderPair{Key: AlgorithmKey, Value: *(h.algorithm)})
	}
	if h.crv != nil {
		pairs = append(pairs, &HeaderPair{Key: ecdsaCrvKey, Value: *(h.crv)})
	}
	if h.keyID != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyIDKey, Value: *(h.keyID)})
	}
	if h.keyType != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyTypeKey, Value: *(h.keyType)})
	}
	if h.keyUsage != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyUsageKey, Value: *(h.keyUsage)})
	}
	if h.keyops != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyOpsKey, Value: h.keyops})
	}
	if h.x != nil {
		pairs = append(pairs, &HeaderPair{Key: ecdsaXKey, Value: h.x})
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
	if h.y != nil {
		pairs = append(pairs, &HeaderPair{Key: ecdsaYKey, Value: h.y})
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

func (h *ECDSAPublicKey) PrivateParams() map[string]interface{} {
	return h.privateParams
}

func (h *ECDSAPublicKey) Get(name string) (interface{}, bool) {
	switch name {
	case AlgorithmKey:
		if h.algorithm == nil {
			return nil, false
		}
		return *(h.algorithm), true
	case ecdsaCrvKey:
		if h.crv == nil {
			return nil, false
		}
		return *(h.crv), true
	case KeyIDKey:
		if h.keyID == nil {
			return nil, false
		}
		return *(h.keyID), true
	case KeyTypeKey:
		if h.keyType == nil {
			return nil, false
		}
		return *(h.keyType), true
	case KeyUsageKey:
		if h.keyUsage == nil {
			return nil, false
		}
		return *(h.keyUsage), true
	case KeyOpsKey:
		if h.keyops == nil {
			return nil, false
		}
		return h.keyops, true
	case ecdsaXKey:
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
	case ecdsaYKey:
		if h.y == nil {
			return nil, false
		}
		return h.y, true
	default:
		v, ok := h.privateParams[name]
		return v, ok
	}
}

func (h *ECDSAPublicKey) Set(name string, value interface{}) error {
	switch name {
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
	case ecdsaCrvKey:
		if v, ok := value.(jwa.EllipticCurveAlgorithm); ok {
			h.crv = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ecdsaCrvKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case KeyTypeKey:
		var acceptor jwa.KeyType
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, KeyTypeKey)
		}
		h.keyType = &acceptor
		return nil
	case KeyUsageKey:
		if v, ok := value.(string); ok {
			h.keyUsage = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyUsageKey, value)
	case KeyOpsKey:
		var acceptor KeyOperationList
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, KeyOpsKey)
		}
		h.keyops = acceptor
		return nil
	case ecdsaXKey:
		if v, ok := value.([]byte); ok {
			h.x = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ecdsaXKey, value)
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
	case ecdsaYKey:
		if v, ok := value.([]byte); ok {
			h.y = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ecdsaYKey, value)
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

func (h *ECDSAPublicKey) UnmarshalJSON(buf []byte) error {
	var proxy ecdsaPublicKeyMarshalProxy
	if err := json.Unmarshal(buf, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmarshal ECDSAPublicKey`)
	}
	h.algorithm = proxy.Xalgorithm
	h.crv = proxy.Xcrv
	h.keyID = proxy.XkeyID
	h.keyType = proxy.XkeyType
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
	if proxy.Xy == nil {
		return errors.New(`required field y is missing`)
	}
	if h.y = nil; proxy.Xy != nil {
		decoded, err := base64.DecodeString(*(proxy.Xy))
		if err != nil {
			return errors.Wrap(err, `failed to decode base64 value for y`)
		}
		h.y = decoded
	}
	var m map[string]interface{}
	if err := json.Unmarshal(buf, &m); err != nil {
		return errors.Wrap(err, `failed to parse privsate parameters`)
	}
	delete(m, AlgorithmKey)
	delete(m, ecdsaCrvKey)
	delete(m, KeyIDKey)
	delete(m, KeyTypeKey)
	delete(m, KeyUsageKey)
	delete(m, KeyOpsKey)
	delete(m, ecdsaXKey)
	delete(m, X509CertChainKey)
	delete(m, X509CertThumbprintKey)
	delete(m, X509CertThumbprintS256Key)
	delete(m, X509URLKey)
	delete(m, ecdsaYKey)
	h.privateParams = m
	return nil
}

func (h ECDSAPublicKey) MarshalJSON() ([]byte, error) {
	var proxy ecdsaPublicKeyMarshalProxy
	proxy.Xalgorithm = h.algorithm
	proxy.Xcrv = h.crv
	proxy.XkeyID = h.keyID
	proxy.XkeyType = h.keyType
	if proxy.XkeyType == nil {
		v := jwa.EC
		proxy.XkeyType = &v
	}
	proxy.XkeyUsage = h.keyUsage
	proxy.Xkeyops = h.keyops
	if len(h.x) > 0 {
		v := base64.EncodeToStringStd(h.x)
		proxy.Xx = &v
	}
	proxy.Xx509CertChain = h.x509CertChain
	proxy.Xx509CertThumbprint = h.x509CertThumbprint
	proxy.Xx509CertThumbprintS256 = h.x509CertThumbprintS256
	proxy.Xx509URL = h.x509URL
	if len(h.y) > 0 {
		v := base64.EncodeToStringStd(h.y)
		proxy.Xy = &v
	}
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

func (h *ECDSAPublicKey) Iterate(ctx context.Context) HeaderIterator {
	ch := make(chan *HeaderPair)
	go h.iterate(ctx, ch)
	return mapiter.New(ch)
}

func (h *ECDSAPublicKey) Walk(ctx context.Context, visitor HeaderVisitor) error {
	return iter.WalkMap(ctx, h, visitor)
}

func (h *ECDSAPublicKey) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return iter.AsMap(ctx, h)
}
