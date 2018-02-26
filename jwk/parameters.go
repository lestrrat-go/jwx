package jwk

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/pdebug"
	"github.com/pkg/errors"
)

const (
	AlgorithmKey              = "alg"
	KeyIDKey                  = "kid"
	KeyTypeKey                = "kty"
	KeyUsageKey               = "use"
	KeyOpsKey                 = "key_ops"
	X509CertChainKey          = "x5c"
	X509CertThumbprintKey     = "x5t"
	X509CertThumbprintS256Key = "x5t#S256"
	X509URLKey                = "x5u"
)

// Parameters interface holds functions for interacting with the JWK.
type Parameters interface {
	Remove(string)
	Get(string) (interface{}, bool)
	Set(string, interface{}) error
	PopulateMap(map[string]interface{}) error
	ExtractMap(map[string]interface{}) error
	Walk(func(string, interface{}) error) error
	Algorithm() string
	KeyID() string
	KeyType() jwa.KeyType
	KeyUsage() string
	KeyOps() []KeyOperation
	X509CertChain() []*x509.Certificate
	X509CertThumbprint() string
	X509CertThumbprintS256() string
	X509URL() string
}

// StandardParameters holds paramters according to JWK rfc 7517.
type StandardParameters struct {
	algorithm              *string           // https://tools.ietf.org/html/rfc7517#section-4.4
	keyID                  *string           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyType                *jwa.KeyType      // https://tools.ietf.org/html/rfc7517#section-4.1
	keyUsage               *string           // https://tools.ietf.org/html/rfc7517#section-4.2
	keyops                 []KeyOperation    // https://tools.ietf.org/html/rfc7517#section-4.3
	x509CertChain          *CertificateChain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string           // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string           // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string           // https://tools.ietf.org/html/rfc7515#section-4.1.5
	privateParams          map[string]interface{}
}

func (h *StandardParameters) Remove(s string) {
	delete(h.privateParams, s)
}

func (h *StandardParameters) Algorithm() string {
	if v := h.algorithm; v != nil {
		return *v
	}
	return ""
}

func (h *StandardParameters) KeyID() string {
	if v := h.keyID; v != nil {
		return *v
	}
	return ""
}

func (h *StandardParameters) KeyType() jwa.KeyType {
	if v := h.keyType; v != nil {
		return *v
	}
	return jwa.InvalidKeyType
}

func (h *StandardParameters) KeyUsage() string {
	if v := h.keyUsage; v != nil {
		return *v
	}
	return ""
}

func (h *StandardParameters) KeyOps() []KeyOperation {
	return h.keyops
}

func (h *StandardParameters) X509CertChain() []*x509.Certificate {
	return h.x509CertChain.Get()
}

func (h *StandardParameters) X509CertThumbprint() string {
	if v := h.x509CertThumbprint; v != nil {
		return *v
	}
	return ""
}

func (h *StandardParameters) X509CertThumbprintS256() string {
	if v := h.x509CertThumbprintS256; v != nil {
		return *v
	}
	return ""
}

func (h *StandardParameters) X509URL() string {
	if v := h.x509URL; v != nil {
		return *v
	}
	return ""
}

func (h *StandardParameters) Get(name string) (interface{}, bool) {
	switch name {
	case AlgorithmKey:
		v := h.algorithm
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
	case KeyTypeKey:
		v := h.keyType
		if v == nil {
			return nil, false
		}
		return *v, true
	case KeyUsageKey:
		v := h.keyUsage
		if v == nil {
			return nil, false
		}
		return *v, true
	case KeyOpsKey:
		v := h.keyops
		if len(v) == 0 {
			return nil, false
		}
		return v, true
	case X509CertChainKey:
		v := h.x509CertChain
		if v == nil {
			return nil, false
		}
		return v.Get(), true
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

func (h *StandardParameters) Set(name string, value interface{}) error {
	switch name {
	case AlgorithmKey:
		switch v := value.(type) {
		case string:
			h.algorithm = &v
			return nil
		case fmt.Stringer:
			s := v.String()
			h.algorithm = &s
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, AlgorithmKey, value)
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
		if v, ok := value.([]KeyOperation); ok {
			h.keyops = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyOpsKey, value)
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

func (h StandardParameters) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{}
	if err := h.PopulateMap(m); err != nil {
		return nil, errors.Wrap(err, `failed to populate map for serialization`)
	}

	return json.Marshal(m)
}

// PopulateMap populates a map with appropriate values that represent
// the parameters as a JSON object. This exists primarily because JWKs are
// represented as flat objects instead of differentiating the different
// parts of the message in separate sub objects.
func (h StandardParameters) PopulateMap(m map[string]interface{}) error {
	for k, v := range h.privateParams {
		m[k] = v
	}
	if v, ok := h.Get(AlgorithmKey); ok {
		m[AlgorithmKey] = v
	}
	if v, ok := h.Get(KeyIDKey); ok {
		m[KeyIDKey] = v
	}
	if v, ok := h.Get(KeyTypeKey); ok {
		m[KeyTypeKey] = v
	}
	if v, ok := h.Get(KeyUsageKey); ok {
		m[KeyUsageKey] = v
	}
	if v, ok := h.Get(KeyOpsKey); ok {
		m[KeyOpsKey] = v
	}
	if v, ok := h.Get(X509CertChainKey); ok {
		m[X509CertChainKey] = v
	}
	if v, ok := h.Get(X509CertThumbprintKey); ok {
		m[X509CertThumbprintKey] = v
	}
	if v, ok := h.Get(X509CertThumbprintS256Key); ok {
		m[X509CertThumbprintS256Key] = v
	}
	if v, ok := h.Get(X509URLKey); ok {
		m[X509URLKey] = v
	}

	return nil
}

// ExtractMap populates the appropriate values from a map that represent
// the parameters as a JSON object. This exists primarily because JWKs are
// represented as flat objects instead of differentiating the different
// parts of the message in separate sub objects.
func (h *StandardParameters) ExtractMap(m map[string]interface{}) (err error) {
	if pdebug.Enabled {
		g := pdebug.Marker(`jwk.StandardParameters.ExtractMap`).BindError(&err)
		defer g.End()
	}
	if v, ok := m[AlgorithmKey]; ok {
		if err := h.Set(AlgorithmKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, AlgorithmKey)
		}
	}
	if v, ok := m[KeyIDKey]; ok {
		if err := h.Set(KeyIDKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, KeyIDKey)
		}
	}
	if v, ok := m[KeyTypeKey]; ok {
		if err := h.Set(KeyTypeKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, KeyTypeKey)
		}
	}
	if v, ok := m[KeyUsageKey]; ok {
		if err := h.Set(KeyUsageKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, KeyUsageKey)
		}
	}
	if v, ok := m[KeyOpsKey]; ok {
		if err := h.Set(KeyOpsKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, KeyOpsKey)
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

func (h *StandardParameters) UnmarshalJSON(buf []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(buf, &m); err != nil {
		return errors.Wrap(err, `failed to unmarshal parameters`)
	}

	return h.ExtractMap(m)
}

func (h StandardParameters) Walk(f func(string, interface{}) error) error {
	for _, key := range []string{AlgorithmKey, KeyIDKey, KeyTypeKey, KeyUsageKey, KeyOpsKey, X509CertChainKey, X509CertThumbprintKey, X509CertThumbprintS256Key, X509URLKey} {
		if v, ok := h.Get(key); ok {
			if err := f(key, v); err != nil {
				return errors.Wrapf(err, `walk function returned error for %s`, key)
			}
		}
	}

	for k, v := range h.privateParams {
		if err := f(k, v); err != nil {
			return errors.Wrapf(err, `walk function returned error for %s`, k)
		}
	}
	return nil
}
