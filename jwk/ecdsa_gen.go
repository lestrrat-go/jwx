// Code generated by tools/cmd/genjwk/main.go. DO NOT EDIT.

package jwk

import (
	"bytes"
	"fmt"
	"sort"
	"sync"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

const (
	ECDSACrvKey = "crv"
	ECDSADKey   = "d"
	ECDSAXKey   = "x"
	ECDSAYKey   = "y"
)

type ECDSAPublicKey interface {
	Key
	Crv() jwa.EllipticCurveAlgorithm
	X() []byte
	Y() []byte
}

type ecdsaPublicKey struct {
	algorithm              *jwa.KeyAlgorithm // https://tools.ietf.org/html/rfc7517#section-4.4
	crv                    *jwa.EllipticCurveAlgorithm
	keyID                  *string           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyOps                 *KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	keyUsage               *string           // https://tools.ietf.org/html/rfc7517#section-4.2
	x                      []byte
	x509CertChain          *cert.Chain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string     // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string     // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string     // https://tools.ietf.org/html/rfc7515#section-4.1.5
	y                      []byte
	privateParams          map[string]interface{}
	mu                     *sync.RWMutex
	dc                     json.DecodeCtx
}

var _ ECDSAPublicKey = &ecdsaPublicKey{}
var _ Key = &ecdsaPublicKey{}

func newECDSAPublicKey() *ecdsaPublicKey {
	return &ecdsaPublicKey{
		mu:            &sync.RWMutex{},
		privateParams: make(map[string]interface{}),
	}
}

func (h ecdsaPublicKey) KeyType() jwa.KeyType {
	return jwa.EC()
}

func (h ecdsaPublicKey) IsPrivate() bool {
	return false
}

func (h *ecdsaPublicKey) Algorithm() jwa.KeyAlgorithm {
	if h.algorithm != nil {
		return *(h.algorithm)
	}
	return nil
}

func (h *ecdsaPublicKey) Crv() jwa.EllipticCurveAlgorithm {
	if h.crv != nil {
		return *(h.crv)
	}
	return jwa.InvalidEllipticCurve()
}

func (h *ecdsaPublicKey) KeyID() string {
	if h.keyID != nil {
		return *(h.keyID)
	}
	return ""
}

func (h *ecdsaPublicKey) KeyOps() KeyOperationList {
	if h.keyOps != nil {
		return *(h.keyOps)
	}
	return nil
}

func (h *ecdsaPublicKey) KeyUsage() string {
	if h.keyUsage != nil {
		return *(h.keyUsage)
	}
	return ""
}

func (h *ecdsaPublicKey) X() []byte {
	return h.x
}

func (h *ecdsaPublicKey) X509CertChain() *cert.Chain {
	return h.x509CertChain
}

func (h *ecdsaPublicKey) X509CertThumbprint() string {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint)
	}
	return ""
}

func (h *ecdsaPublicKey) X509CertThumbprintS256() string {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256)
	}
	return ""
}

func (h *ecdsaPublicKey) X509URL() string {
	if h.x509URL != nil {
		return *(h.x509URL)
	}
	return ""
}

func (h *ecdsaPublicKey) Y() []byte {
	return h.y
}

func (h *ecdsaPublicKey) Has(name string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case AlgorithmKey:
		return h.algorithm != nil
	case ECDSACrvKey:
		return h.crv != nil
	case KeyIDKey:
		return h.keyID != nil
	case KeyOpsKey:
		return h.keyOps != nil
	case KeyUsageKey:
		return h.keyUsage != nil
	case ECDSAXKey:
		return h.x != nil
	case X509CertChainKey:
		return h.x509CertChain != nil
	case X509CertThumbprintKey:
		return h.x509CertThumbprint != nil
	case X509CertThumbprintS256Key:
		return h.x509CertThumbprintS256 != nil
	case X509URLKey:
		return h.x509URL != nil
	case ECDSAYKey:
		return h.y != nil
	default:
		_, ok := h.privateParams[name]
		return ok
	}
}

func (h *ecdsaPublicKey) Get(name string, dst interface{}) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case KeyTypeKey:
		if err := blackmagic.AssignIfCompatible(dst, h.KeyType()); err != nil {
			return fmt.Errorf(`ecdsaPublicKey.Get: failed to assign value for field %q to destination object: %w`, name, err)
		}
	case AlgorithmKey:
		if h.algorithm == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.algorithm)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case ECDSACrvKey:
		if h.crv == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.crv)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case KeyIDKey:
		if h.keyID == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.keyID)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case KeyOpsKey:
		if h.keyOps == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.keyOps)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case KeyUsageKey:
		if h.keyUsage == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.keyUsage)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case ECDSAXKey:
		if h.x == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.x); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509CertChainKey:
		if h.x509CertChain == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.x509CertChain); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509CertThumbprintKey:
		if h.x509CertThumbprint == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.x509CertThumbprint)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509CertThumbprintS256Key:
		if h.x509CertThumbprintS256 == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.x509CertThumbprintS256)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509URLKey:
		if h.x509URL == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.x509URL)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case ECDSAYKey:
		if h.y == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.y); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	default:
		v, ok := h.privateParams[name]
		if !ok {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, v); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
	}
	return nil
}

func (h *ecdsaPublicKey) Set(name string, value interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.setNoLock(name, value)
}

func (h *ecdsaPublicKey) setNoLock(name string, value interface{}) error {
	switch name {
	case "kty":
		return nil
	case AlgorithmKey:
		switch v := value.(type) {
		case string, jwa.SignatureAlgorithm, jwa.ContentEncryptionAlgorithm:
			tmp, err := jwa.KeyAlgorithmFrom(v)
			if err != nil {
				return fmt.Errorf(`invalid algorithm for %s key: %w`, AlgorithmKey, err)
			}
			h.algorithm = &tmp
		default:
			return fmt.Errorf(`invalid type for %s key: %T`, AlgorithmKey, value)
		}
		return nil
	case ECDSACrvKey:
		if v, ok := value.(jwa.EllipticCurveAlgorithm); ok {
			h.crv = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, ECDSACrvKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case KeyOpsKey:
		var acceptor KeyOperationList
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, KeyOpsKey, err)
		}
		h.keyOps = &acceptor
		return nil
	case KeyUsageKey:
		switch v := value.(type) {
		case KeyUsageType:
			switch v {
			case ForSignature, ForEncryption:
				tmp := v.String()
				h.keyUsage = &tmp
			default:
				return fmt.Errorf(`invalid key usage type %s`, v)
			}
		case string:
			h.keyUsage = &v
		default:
			return fmt.Errorf(`invalid key usage type %s`, v)
		}
	case ECDSAXKey:
		if v, ok := value.([]byte); ok {
			h.x = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, ECDSAXKey, value)
	case X509CertChainKey:
		if v, ok := value.(*cert.Chain); ok {
			h.x509CertChain = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509CertChainKey, value)
	case X509CertThumbprintKey:
		if v, ok := value.(string); ok {
			h.x509CertThumbprint = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509CertThumbprintKey, value)
	case X509CertThumbprintS256Key:
		if v, ok := value.(string); ok {
			h.x509CertThumbprintS256 = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509CertThumbprintS256Key, value)
	case X509URLKey:
		if v, ok := value.(string); ok {
			h.x509URL = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509URLKey, value)
	case ECDSAYKey:
		if v, ok := value.([]byte); ok {
			h.y = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, ECDSAYKey, value)
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

func (k *ecdsaPublicKey) Remove(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch key {
	case AlgorithmKey:
		k.algorithm = nil
	case ECDSACrvKey:
		k.crv = nil
	case KeyIDKey:
		k.keyID = nil
	case KeyOpsKey:
		k.keyOps = nil
	case KeyUsageKey:
		k.keyUsage = nil
	case ECDSAXKey:
		k.x = nil
	case X509CertChainKey:
		k.x509CertChain = nil
	case X509CertThumbprintKey:
		k.x509CertThumbprint = nil
	case X509CertThumbprintS256Key:
		k.x509CertThumbprintS256 = nil
	case X509URLKey:
		k.x509URL = nil
	case ECDSAYKey:
		k.y = nil
	default:
		delete(k.privateParams, key)
	}
	return nil
}

func (k *ecdsaPublicKey) Clone() (Key, error) {
	key, err := cloneKey(k)
	if err != nil {
		return nil, fmt.Errorf(`ecdsaPublicKey.Clone: %w`, err)
	}
	return key, nil
}

func (k *ecdsaPublicKey) DecodeCtx() json.DecodeCtx {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.dc
}

func (k *ecdsaPublicKey) SetDecodeCtx(dc json.DecodeCtx) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dc = dc
}

func (h *ecdsaPublicKey) UnmarshalJSON(buf []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.algorithm = nil
	h.crv = nil
	h.keyID = nil
	h.keyOps = nil
	h.keyUsage = nil
	h.x = nil
	h.x509CertChain = nil
	h.x509CertThumbprint = nil
	h.x509CertThumbprintS256 = nil
	h.x509URL = nil
	h.y = nil
	dec := json.NewDecoder(bytes.NewReader(buf))
LOOP:
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf(`error reading token: %w`, err)
		}
		switch tok := tok.(type) {
		case json.Delim:
			// Assuming we're doing everything correctly, we should ONLY
			// get either '{' or '}' here.
			if tok == '}' { // End of object
				break LOOP
			} else if tok != '{' {
				return fmt.Errorf(`expected '{', but got '%c'`, tok)
			}
		case string: // Objects can only have string keys
			switch tok {
			case KeyTypeKey:
				val, err := json.ReadNextStringToken(dec)
				if err != nil {
					return fmt.Errorf(`error reading token: %w`, err)
				}
				if val != jwa.EC().String() {
					return fmt.Errorf(`invalid kty value for RSAPublicKey (%s)`, val)
				}
			case AlgorithmKey:
				var s string
				if err := dec.Decode(&s); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, AlgorithmKey, err)
				}
				alg, err := jwa.KeyAlgorithmFrom(s)
				if err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, AlgorithmKey, err)
				}
				h.algorithm = &alg
			case ECDSACrvKey:
				var decoded jwa.EllipticCurveAlgorithm
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, ECDSACrvKey, err)
				}
				h.crv = &decoded
			case KeyIDKey:
				if err := json.AssignNextStringToken(&h.keyID, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, KeyIDKey, err)
				}
			case KeyOpsKey:
				var decoded KeyOperationList
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, KeyOpsKey, err)
				}
				h.keyOps = &decoded
			case KeyUsageKey:
				if err := json.AssignNextStringToken(&h.keyUsage, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, KeyUsageKey, err)
				}
			case ECDSAXKey:
				if err := json.AssignNextBytesToken(&h.x, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, ECDSAXKey, err)
				}
			case X509CertChainKey:
				var decoded cert.Chain
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509CertChainKey, err)
				}
				h.x509CertChain = &decoded
			case X509CertThumbprintKey:
				if err := json.AssignNextStringToken(&h.x509CertThumbprint, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509CertThumbprintKey, err)
				}
			case X509CertThumbprintS256Key:
				if err := json.AssignNextStringToken(&h.x509CertThumbprintS256, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509CertThumbprintS256Key, err)
				}
			case X509URLKey:
				if err := json.AssignNextStringToken(&h.x509URL, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509URLKey, err)
				}
			case ECDSAYKey:
				if err := json.AssignNextBytesToken(&h.y, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, ECDSAYKey, err)
				}
			default:
				if dc := h.dc; dc != nil {
					if localReg := dc.Registry(); localReg != nil {
						decoded, err := localReg.Decode(dec, tok)
						if err == nil {
							h.setNoLock(tok, decoded)
							continue
						}
					}
				}
				decoded, err := registry.Decode(dec, tok)
				if err == nil {
					h.setNoLock(tok, decoded)
					continue
				}
				return fmt.Errorf(`could not decode field %s: %w`, tok, err)
			}
		default:
			return fmt.Errorf(`invalid token %T`, tok)
		}
	}
	if h.crv == nil {
		return fmt.Errorf(`required field crv is missing`)
	}
	if h.x == nil {
		return fmt.Errorf(`required field x is missing`)
	}
	if h.y == nil {
		return fmt.Errorf(`required field y is missing`)
	}
	return nil
}

func (h ecdsaPublicKey) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	fields := make([]string, 0, 11)
	data[KeyTypeKey] = jwa.EC()
	fields = append(fields, KeyTypeKey)
	if h.algorithm != nil {
		data[AlgorithmKey] = *(h.algorithm)
		fields = append(fields, AlgorithmKey)
	}
	if h.crv != nil {
		data[ECDSACrvKey] = *(h.crv)
		fields = append(fields, ECDSACrvKey)
	}
	if h.keyID != nil {
		data[KeyIDKey] = *(h.keyID)
		fields = append(fields, KeyIDKey)
	}
	if h.keyOps != nil {
		data[KeyOpsKey] = *(h.keyOps)
		fields = append(fields, KeyOpsKey)
	}
	if h.keyUsage != nil {
		data[KeyUsageKey] = *(h.keyUsage)
		fields = append(fields, KeyUsageKey)
	}
	if h.x != nil {
		data[ECDSAXKey] = h.x
		fields = append(fields, ECDSAXKey)
	}
	if h.x509CertChain != nil {
		data[X509CertChainKey] = h.x509CertChain
		fields = append(fields, X509CertChainKey)
	}
	if h.x509CertThumbprint != nil {
		data[X509CertThumbprintKey] = *(h.x509CertThumbprint)
		fields = append(fields, X509CertThumbprintKey)
	}
	if h.x509CertThumbprintS256 != nil {
		data[X509CertThumbprintS256Key] = *(h.x509CertThumbprintS256)
		fields = append(fields, X509CertThumbprintS256Key)
	}
	if h.x509URL != nil {
		data[X509URLKey] = *(h.x509URL)
		fields = append(fields, X509URLKey)
	}
	if h.y != nil {
		data[ECDSAYKey] = h.y
		fields = append(fields, ECDSAYKey)
	}
	for k, v := range h.privateParams {
		data[k] = v
		fields = append(fields, k)
	}

	sort.Strings(fields)
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)
	buf.WriteByte('{')
	enc := json.NewEncoder(buf)
	for i, f := range fields {
		if i > 0 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(f)
		buf.WriteString(`":`)
		v := data[f]
		switch v := v.(type) {
		case []byte:
			buf.WriteRune('"')
			buf.WriteString(base64.EncodeToString(v))
			buf.WriteRune('"')
		default:
			if err := enc.Encode(v); err != nil {
				return nil, fmt.Errorf(`failed to encode value for field %s: %w`, f, err)
			}
			buf.Truncate(buf.Len() - 1)
		}
	}
	buf.WriteByte('}')
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

func (h *ecdsaPublicKey) Keys() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	keys := make([]string, 0, 11+len(h.privateParams))
	keys = append(keys, KeyTypeKey)
	if h.algorithm != nil {
		keys = append(keys, AlgorithmKey)
	}
	if h.crv != nil {
		keys = append(keys, ECDSACrvKey)
	}
	if h.keyID != nil {
		keys = append(keys, KeyIDKey)
	}
	if h.keyOps != nil {
		keys = append(keys, KeyOpsKey)
	}
	if h.keyUsage != nil {
		keys = append(keys, KeyUsageKey)
	}
	if h.x != nil {
		keys = append(keys, ECDSAXKey)
	}
	if h.x509CertChain != nil {
		keys = append(keys, X509CertChainKey)
	}
	if h.x509CertThumbprint != nil {
		keys = append(keys, X509CertThumbprintKey)
	}
	if h.x509CertThumbprintS256 != nil {
		keys = append(keys, X509CertThumbprintS256Key)
	}
	if h.x509URL != nil {
		keys = append(keys, X509URLKey)
	}
	if h.y != nil {
		keys = append(keys, ECDSAYKey)
	}
	for k := range h.privateParams {
		keys = append(keys, k)
	}
	return keys
}

type ECDSAPrivateKey interface {
	Key
	Crv() jwa.EllipticCurveAlgorithm
	D() []byte
	X() []byte
	Y() []byte
}

type ecdsaPrivateKey struct {
	algorithm              *jwa.KeyAlgorithm // https://tools.ietf.org/html/rfc7517#section-4.4
	crv                    *jwa.EllipticCurveAlgorithm
	d                      []byte
	keyID                  *string           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyOps                 *KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	keyUsage               *string           // https://tools.ietf.org/html/rfc7517#section-4.2
	x                      []byte
	x509CertChain          *cert.Chain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string     // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string     // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string     // https://tools.ietf.org/html/rfc7515#section-4.1.5
	y                      []byte
	privateParams          map[string]interface{}
	mu                     *sync.RWMutex
	dc                     json.DecodeCtx
}

var _ ECDSAPrivateKey = &ecdsaPrivateKey{}
var _ Key = &ecdsaPrivateKey{}

func newECDSAPrivateKey() *ecdsaPrivateKey {
	return &ecdsaPrivateKey{
		mu:            &sync.RWMutex{},
		privateParams: make(map[string]interface{}),
	}
}

func (h ecdsaPrivateKey) KeyType() jwa.KeyType {
	return jwa.EC()
}

func (h ecdsaPrivateKey) IsPrivate() bool {
	return true
}

func (h *ecdsaPrivateKey) Algorithm() jwa.KeyAlgorithm {
	if h.algorithm != nil {
		return *(h.algorithm)
	}
	return nil
}

func (h *ecdsaPrivateKey) Crv() jwa.EllipticCurveAlgorithm {
	if h.crv != nil {
		return *(h.crv)
	}
	return jwa.InvalidEllipticCurve()
}

func (h *ecdsaPrivateKey) D() []byte {
	return h.d
}

func (h *ecdsaPrivateKey) KeyID() string {
	if h.keyID != nil {
		return *(h.keyID)
	}
	return ""
}

func (h *ecdsaPrivateKey) KeyOps() KeyOperationList {
	if h.keyOps != nil {
		return *(h.keyOps)
	}
	return nil
}

func (h *ecdsaPrivateKey) KeyUsage() string {
	if h.keyUsage != nil {
		return *(h.keyUsage)
	}
	return ""
}

func (h *ecdsaPrivateKey) X() []byte {
	return h.x
}

func (h *ecdsaPrivateKey) X509CertChain() *cert.Chain {
	return h.x509CertChain
}

func (h *ecdsaPrivateKey) X509CertThumbprint() string {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint)
	}
	return ""
}

func (h *ecdsaPrivateKey) X509CertThumbprintS256() string {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256)
	}
	return ""
}

func (h *ecdsaPrivateKey) X509URL() string {
	if h.x509URL != nil {
		return *(h.x509URL)
	}
	return ""
}

func (h *ecdsaPrivateKey) Y() []byte {
	return h.y
}

func (h *ecdsaPrivateKey) Has(name string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case AlgorithmKey:
		return h.algorithm != nil
	case ECDSACrvKey:
		return h.crv != nil
	case ECDSADKey:
		return h.d != nil
	case KeyIDKey:
		return h.keyID != nil
	case KeyOpsKey:
		return h.keyOps != nil
	case KeyUsageKey:
		return h.keyUsage != nil
	case ECDSAXKey:
		return h.x != nil
	case X509CertChainKey:
		return h.x509CertChain != nil
	case X509CertThumbprintKey:
		return h.x509CertThumbprint != nil
	case X509CertThumbprintS256Key:
		return h.x509CertThumbprintS256 != nil
	case X509URLKey:
		return h.x509URL != nil
	case ECDSAYKey:
		return h.y != nil
	default:
		_, ok := h.privateParams[name]
		return ok
	}
}

func (h *ecdsaPrivateKey) Get(name string, dst interface{}) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case KeyTypeKey:
		if err := blackmagic.AssignIfCompatible(dst, h.KeyType()); err != nil {
			return fmt.Errorf(`ecdsaPrivateKey.Get: failed to assign value for field %q to destination object: %w`, name, err)
		}
	case AlgorithmKey:
		if h.algorithm == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.algorithm)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case ECDSACrvKey:
		if h.crv == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.crv)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case ECDSADKey:
		if h.d == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.d); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case KeyIDKey:
		if h.keyID == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.keyID)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case KeyOpsKey:
		if h.keyOps == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.keyOps)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case KeyUsageKey:
		if h.keyUsage == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.keyUsage)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case ECDSAXKey:
		if h.x == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.x); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509CertChainKey:
		if h.x509CertChain == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.x509CertChain); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509CertThumbprintKey:
		if h.x509CertThumbprint == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.x509CertThumbprint)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509CertThumbprintS256Key:
		if h.x509CertThumbprintS256 == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.x509CertThumbprintS256)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509URLKey:
		if h.x509URL == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.x509URL)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case ECDSAYKey:
		if h.y == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.y); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	default:
		v, ok := h.privateParams[name]
		if !ok {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, v); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
	}
	return nil
}

func (h *ecdsaPrivateKey) Set(name string, value interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.setNoLock(name, value)
}

func (h *ecdsaPrivateKey) setNoLock(name string, value interface{}) error {
	switch name {
	case "kty":
		return nil
	case AlgorithmKey:
		switch v := value.(type) {
		case string, jwa.SignatureAlgorithm, jwa.ContentEncryptionAlgorithm:
			tmp, err := jwa.KeyAlgorithmFrom(v)
			if err != nil {
				return fmt.Errorf(`invalid algorithm for %s key: %w`, AlgorithmKey, err)
			}
			h.algorithm = &tmp
		default:
			return fmt.Errorf(`invalid type for %s key: %T`, AlgorithmKey, value)
		}
		return nil
	case ECDSACrvKey:
		if v, ok := value.(jwa.EllipticCurveAlgorithm); ok {
			h.crv = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, ECDSACrvKey, value)
	case ECDSADKey:
		if v, ok := value.([]byte); ok {
			h.d = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, ECDSADKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case KeyOpsKey:
		var acceptor KeyOperationList
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, KeyOpsKey, err)
		}
		h.keyOps = &acceptor
		return nil
	case KeyUsageKey:
		switch v := value.(type) {
		case KeyUsageType:
			switch v {
			case ForSignature, ForEncryption:
				tmp := v.String()
				h.keyUsage = &tmp
			default:
				return fmt.Errorf(`invalid key usage type %s`, v)
			}
		case string:
			h.keyUsage = &v
		default:
			return fmt.Errorf(`invalid key usage type %s`, v)
		}
	case ECDSAXKey:
		if v, ok := value.([]byte); ok {
			h.x = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, ECDSAXKey, value)
	case X509CertChainKey:
		if v, ok := value.(*cert.Chain); ok {
			h.x509CertChain = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509CertChainKey, value)
	case X509CertThumbprintKey:
		if v, ok := value.(string); ok {
			h.x509CertThumbprint = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509CertThumbprintKey, value)
	case X509CertThumbprintS256Key:
		if v, ok := value.(string); ok {
			h.x509CertThumbprintS256 = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509CertThumbprintS256Key, value)
	case X509URLKey:
		if v, ok := value.(string); ok {
			h.x509URL = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509URLKey, value)
	case ECDSAYKey:
		if v, ok := value.([]byte); ok {
			h.y = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, ECDSAYKey, value)
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

func (k *ecdsaPrivateKey) Remove(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch key {
	case AlgorithmKey:
		k.algorithm = nil
	case ECDSACrvKey:
		k.crv = nil
	case ECDSADKey:
		k.d = nil
	case KeyIDKey:
		k.keyID = nil
	case KeyOpsKey:
		k.keyOps = nil
	case KeyUsageKey:
		k.keyUsage = nil
	case ECDSAXKey:
		k.x = nil
	case X509CertChainKey:
		k.x509CertChain = nil
	case X509CertThumbprintKey:
		k.x509CertThumbprint = nil
	case X509CertThumbprintS256Key:
		k.x509CertThumbprintS256 = nil
	case X509URLKey:
		k.x509URL = nil
	case ECDSAYKey:
		k.y = nil
	default:
		delete(k.privateParams, key)
	}
	return nil
}

func (k *ecdsaPrivateKey) Clone() (Key, error) {
	key, err := cloneKey(k)
	if err != nil {
		return nil, fmt.Errorf(`ecdsaPrivateKey.Clone: %w`, err)
	}
	return key, nil
}

func (k *ecdsaPrivateKey) DecodeCtx() json.DecodeCtx {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.dc
}

func (k *ecdsaPrivateKey) SetDecodeCtx(dc json.DecodeCtx) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dc = dc
}

func (h *ecdsaPrivateKey) UnmarshalJSON(buf []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.algorithm = nil
	h.crv = nil
	h.d = nil
	h.keyID = nil
	h.keyOps = nil
	h.keyUsage = nil
	h.x = nil
	h.x509CertChain = nil
	h.x509CertThumbprint = nil
	h.x509CertThumbprintS256 = nil
	h.x509URL = nil
	h.y = nil
	dec := json.NewDecoder(bytes.NewReader(buf))
LOOP:
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf(`error reading token: %w`, err)
		}
		switch tok := tok.(type) {
		case json.Delim:
			// Assuming we're doing everything correctly, we should ONLY
			// get either '{' or '}' here.
			if tok == '}' { // End of object
				break LOOP
			} else if tok != '{' {
				return fmt.Errorf(`expected '{', but got '%c'`, tok)
			}
		case string: // Objects can only have string keys
			switch tok {
			case KeyTypeKey:
				val, err := json.ReadNextStringToken(dec)
				if err != nil {
					return fmt.Errorf(`error reading token: %w`, err)
				}
				if val != jwa.EC().String() {
					return fmt.Errorf(`invalid kty value for RSAPublicKey (%s)`, val)
				}
			case AlgorithmKey:
				var s string
				if err := dec.Decode(&s); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, AlgorithmKey, err)
				}
				alg, err := jwa.KeyAlgorithmFrom(s)
				if err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, AlgorithmKey, err)
				}
				h.algorithm = &alg
			case ECDSACrvKey:
				var decoded jwa.EllipticCurveAlgorithm
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, ECDSACrvKey, err)
				}
				h.crv = &decoded
			case ECDSADKey:
				if err := json.AssignNextBytesToken(&h.d, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, ECDSADKey, err)
				}
			case KeyIDKey:
				if err := json.AssignNextStringToken(&h.keyID, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, KeyIDKey, err)
				}
			case KeyOpsKey:
				var decoded KeyOperationList
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, KeyOpsKey, err)
				}
				h.keyOps = &decoded
			case KeyUsageKey:
				if err := json.AssignNextStringToken(&h.keyUsage, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, KeyUsageKey, err)
				}
			case ECDSAXKey:
				if err := json.AssignNextBytesToken(&h.x, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, ECDSAXKey, err)
				}
			case X509CertChainKey:
				var decoded cert.Chain
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509CertChainKey, err)
				}
				h.x509CertChain = &decoded
			case X509CertThumbprintKey:
				if err := json.AssignNextStringToken(&h.x509CertThumbprint, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509CertThumbprintKey, err)
				}
			case X509CertThumbprintS256Key:
				if err := json.AssignNextStringToken(&h.x509CertThumbprintS256, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509CertThumbprintS256Key, err)
				}
			case X509URLKey:
				if err := json.AssignNextStringToken(&h.x509URL, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509URLKey, err)
				}
			case ECDSAYKey:
				if err := json.AssignNextBytesToken(&h.y, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, ECDSAYKey, err)
				}
			default:
				if dc := h.dc; dc != nil {
					if localReg := dc.Registry(); localReg != nil {
						decoded, err := localReg.Decode(dec, tok)
						if err == nil {
							h.setNoLock(tok, decoded)
							continue
						}
					}
				}
				decoded, err := registry.Decode(dec, tok)
				if err == nil {
					h.setNoLock(tok, decoded)
					continue
				}
				return fmt.Errorf(`could not decode field %s: %w`, tok, err)
			}
		default:
			return fmt.Errorf(`invalid token %T`, tok)
		}
	}
	if h.crv == nil {
		return fmt.Errorf(`required field crv is missing`)
	}
	if h.d == nil {
		return fmt.Errorf(`required field d is missing`)
	}
	if h.x == nil {
		return fmt.Errorf(`required field x is missing`)
	}
	if h.y == nil {
		return fmt.Errorf(`required field y is missing`)
	}
	return nil
}

func (h ecdsaPrivateKey) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	fields := make([]string, 0, 12)
	data[KeyTypeKey] = jwa.EC()
	fields = append(fields, KeyTypeKey)
	if h.algorithm != nil {
		data[AlgorithmKey] = *(h.algorithm)
		fields = append(fields, AlgorithmKey)
	}
	if h.crv != nil {
		data[ECDSACrvKey] = *(h.crv)
		fields = append(fields, ECDSACrvKey)
	}
	if h.d != nil {
		data[ECDSADKey] = h.d
		fields = append(fields, ECDSADKey)
	}
	if h.keyID != nil {
		data[KeyIDKey] = *(h.keyID)
		fields = append(fields, KeyIDKey)
	}
	if h.keyOps != nil {
		data[KeyOpsKey] = *(h.keyOps)
		fields = append(fields, KeyOpsKey)
	}
	if h.keyUsage != nil {
		data[KeyUsageKey] = *(h.keyUsage)
		fields = append(fields, KeyUsageKey)
	}
	if h.x != nil {
		data[ECDSAXKey] = h.x
		fields = append(fields, ECDSAXKey)
	}
	if h.x509CertChain != nil {
		data[X509CertChainKey] = h.x509CertChain
		fields = append(fields, X509CertChainKey)
	}
	if h.x509CertThumbprint != nil {
		data[X509CertThumbprintKey] = *(h.x509CertThumbprint)
		fields = append(fields, X509CertThumbprintKey)
	}
	if h.x509CertThumbprintS256 != nil {
		data[X509CertThumbprintS256Key] = *(h.x509CertThumbprintS256)
		fields = append(fields, X509CertThumbprintS256Key)
	}
	if h.x509URL != nil {
		data[X509URLKey] = *(h.x509URL)
		fields = append(fields, X509URLKey)
	}
	if h.y != nil {
		data[ECDSAYKey] = h.y
		fields = append(fields, ECDSAYKey)
	}
	for k, v := range h.privateParams {
		data[k] = v
		fields = append(fields, k)
	}

	sort.Strings(fields)
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)
	buf.WriteByte('{')
	enc := json.NewEncoder(buf)
	for i, f := range fields {
		if i > 0 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(f)
		buf.WriteString(`":`)
		v := data[f]
		switch v := v.(type) {
		case []byte:
			buf.WriteRune('"')
			buf.WriteString(base64.EncodeToString(v))
			buf.WriteRune('"')
		default:
			if err := enc.Encode(v); err != nil {
				return nil, fmt.Errorf(`failed to encode value for field %s: %w`, f, err)
			}
			buf.Truncate(buf.Len() - 1)
		}
	}
	buf.WriteByte('}')
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

func (h *ecdsaPrivateKey) Keys() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	keys := make([]string, 0, 12+len(h.privateParams))
	keys = append(keys, KeyTypeKey)
	if h.algorithm != nil {
		keys = append(keys, AlgorithmKey)
	}
	if h.crv != nil {
		keys = append(keys, ECDSACrvKey)
	}
	if h.d != nil {
		keys = append(keys, ECDSADKey)
	}
	if h.keyID != nil {
		keys = append(keys, KeyIDKey)
	}
	if h.keyOps != nil {
		keys = append(keys, KeyOpsKey)
	}
	if h.keyUsage != nil {
		keys = append(keys, KeyUsageKey)
	}
	if h.x != nil {
		keys = append(keys, ECDSAXKey)
	}
	if h.x509CertChain != nil {
		keys = append(keys, X509CertChainKey)
	}
	if h.x509CertThumbprint != nil {
		keys = append(keys, X509CertThumbprintKey)
	}
	if h.x509CertThumbprintS256 != nil {
		keys = append(keys, X509CertThumbprintS256Key)
	}
	if h.x509URL != nil {
		keys = append(keys, X509URLKey)
	}
	if h.y != nil {
		keys = append(keys, ECDSAYKey)
	}
	for k := range h.privateParams {
		keys = append(keys, k)
	}
	return keys
}
