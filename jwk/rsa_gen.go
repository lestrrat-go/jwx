// Code generated by tools/cmd/genjwk/main.go. DO NOT EDIT.

package jwk

import (
	"bytes"
	"crypto/rsa"
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
	RSADKey  = "d"
	RSADPKey = "dp"
	RSADQKey = "dq"
	RSAEKey  = "e"
	RSANKey  = "n"
	RSAPKey  = "p"
	RSAQIKey = "qi"
	RSAQKey  = "q"
)

type RSAPublicKey interface {
	Key
	FromRaw(*rsa.PublicKey) error
	E() []byte
	N() []byte
}

type rsaPublicKey struct {
	algorithm              *jwa.KeyAlgorithm // https://tools.ietf.org/html/rfc7517#section-4.4
	e                      []byte
	keyID                  *string           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyOps                 *KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	keyUsage               *string           // https://tools.ietf.org/html/rfc7517#section-4.2
	n                      []byte
	x509CertChain          *cert.Chain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string     // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string     // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string     // https://tools.ietf.org/html/rfc7515#section-4.1.5
	privateParams          map[string]interface{}
	mu                     *sync.RWMutex
	dc                     json.DecodeCtx
}

var _ RSAPublicKey = &rsaPublicKey{}
var _ Key = &rsaPublicKey{}

func newRSAPublicKey() *rsaPublicKey {
	return &rsaPublicKey{
		mu:            &sync.RWMutex{},
		privateParams: make(map[string]interface{}),
	}
}

func (h rsaPublicKey) KeyType() jwa.KeyType {
	return jwa.RSA
}

func (h rsaPublicKey) IsPrivate() bool {
	return false
}

func (h *rsaPublicKey) Algorithm() jwa.KeyAlgorithm {
	if h.algorithm != nil {
		return *(h.algorithm)
	}
	return jwa.InvalidKeyAlgorithm("")
}

func (h *rsaPublicKey) E() []byte {
	return h.e
}

func (h *rsaPublicKey) KeyID() string {
	if h.keyID != nil {
		return *(h.keyID)
	}
	return ""
}

func (h *rsaPublicKey) KeyOps() KeyOperationList {
	if h.keyOps != nil {
		return *(h.keyOps)
	}
	return nil
}

func (h *rsaPublicKey) KeyUsage() string {
	if h.keyUsage != nil {
		return *(h.keyUsage)
	}
	return ""
}

func (h *rsaPublicKey) N() []byte {
	return h.n
}

func (h *rsaPublicKey) X509CertChain() *cert.Chain {
	return h.x509CertChain
}

func (h *rsaPublicKey) X509CertThumbprint() string {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint)
	}
	return ""
}

func (h *rsaPublicKey) X509CertThumbprintS256() string {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256)
	}
	return ""
}

func (h *rsaPublicKey) X509URL() string {
	if h.x509URL != nil {
		return *(h.x509URL)
	}
	return ""
}

func (h *rsaPublicKey) makePairs() []*HeaderPair {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var pairs []*HeaderPair
	pairs = append(pairs, &HeaderPair{Key: "kty", Value: jwa.RSA})
	if h.algorithm != nil {
		pairs = append(pairs, &HeaderPair{Key: AlgorithmKey, Value: *(h.algorithm)})
	}
	if h.e != nil {
		pairs = append(pairs, &HeaderPair{Key: RSAEKey, Value: h.e})
	}
	if h.keyID != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyIDKey, Value: *(h.keyID)})
	}
	if h.keyOps != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyOpsKey, Value: *(h.keyOps)})
	}
	if h.keyUsage != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyUsageKey, Value: *(h.keyUsage)})
	}
	if h.n != nil {
		pairs = append(pairs, &HeaderPair{Key: RSANKey, Value: h.n})
	}
	if h.x509CertChain != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertChainKey, Value: h.x509CertChain})
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
	return pairs
}

func (h *rsaPublicKey) PrivateParams() map[string]interface{} {
	return h.privateParams
}

func (h *rsaPublicKey) Has(name string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case AlgorithmKey:
		return h.algorithm != nil
	case RSAEKey:
		return h.e != nil
	case KeyIDKey:
		return h.keyID != nil
	case KeyOpsKey:
		return h.keyOps != nil
	case KeyUsageKey:
		return h.keyUsage != nil
	case RSANKey:
		return h.n != nil
	case X509CertChainKey:
		return h.x509CertChain != nil
	case X509CertThumbprintKey:
		return h.x509CertThumbprint != nil
	case X509CertThumbprintS256Key:
		return h.x509CertThumbprintS256 != nil
	case X509URLKey:
		return h.x509URL != nil
	default:
		_, ok := h.privateParams[name]
		return ok
	}
}

func (h *rsaPublicKey) Get(name string, dst interface{}) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case KeyTypeKey:
		if err := blackmagic.AssignIfCompatible(dst, h.KeyType()); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
	case AlgorithmKey:
		if h.algorithm == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.algorithm)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case RSAEKey:
		if h.e == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.e); err != nil {
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
	case RSANKey:
		if h.n == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.n); err != nil {
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

func (h *rsaPublicKey) Set(name string, value interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.setNoLock(name, value)
}

func (h *rsaPublicKey) setNoLock(name string, value interface{}) error {
	switch name {
	case "kty":
		return nil
	case AlgorithmKey:
		switch v := value.(type) {
		case string, jwa.SignatureAlgorithm, jwa.ContentEncryptionAlgorithm:
			var tmp = jwa.KeyAlgorithmFrom(v)
			h.algorithm = &tmp
		case fmt.Stringer:
			s := v.String()
			var tmp = jwa.KeyAlgorithmFrom(s)
			h.algorithm = &tmp
		default:
			return fmt.Errorf(`invalid type for %s key: %T`, AlgorithmKey, value)
		}
		return nil
	case RSAEKey:
		if v, ok := value.([]byte); ok {
			h.e = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, RSAEKey, value)
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
	case RSANKey:
		if v, ok := value.([]byte); ok {
			h.n = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, RSANKey, value)
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
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

func (k *rsaPublicKey) Remove(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch key {
	case AlgorithmKey:
		k.algorithm = nil
	case RSAEKey:
		k.e = nil
	case KeyIDKey:
		k.keyID = nil
	case KeyOpsKey:
		k.keyOps = nil
	case KeyUsageKey:
		k.keyUsage = nil
	case RSANKey:
		k.n = nil
	case X509CertChainKey:
		k.x509CertChain = nil
	case X509CertThumbprintKey:
		k.x509CertThumbprint = nil
	case X509CertThumbprintS256Key:
		k.x509CertThumbprintS256 = nil
	case X509URLKey:
		k.x509URL = nil
	default:
		delete(k.privateParams, key)
	}
	return nil
}

func (k *rsaPublicKey) Clone() (Key, error) {
	return cloneKey(k)
}

func (k *rsaPublicKey) DecodeCtx() json.DecodeCtx {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.dc
}

func (k *rsaPublicKey) SetDecodeCtx(dc json.DecodeCtx) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dc = dc
}

func (h *rsaPublicKey) UnmarshalJSON(buf []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.algorithm = nil
	h.e = nil
	h.keyID = nil
	h.keyOps = nil
	h.keyUsage = nil
	h.n = nil
	h.x509CertChain = nil
	h.x509CertThumbprint = nil
	h.x509CertThumbprintS256 = nil
	h.x509URL = nil
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
				if val != jwa.RSA.String() {
					return fmt.Errorf(`invalid kty value for RSAPublicKey (%s)`, val)
				}
			case AlgorithmKey:
				var s string
				if err := dec.Decode(&s); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, AlgorithmKey, err)
				}
				alg := jwa.KeyAlgorithmFrom(s)
				h.algorithm = &alg
			case RSAEKey:
				if err := json.AssignNextBytesToken(&h.e, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, RSAEKey, err)
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
			case RSANKey:
				if err := json.AssignNextBytesToken(&h.n, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, RSANKey, err)
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
	if h.e == nil {
		return fmt.Errorf(`required field e is missing`)
	}
	if h.n == nil {
		return fmt.Errorf(`required field n is missing`)
	}
	return nil
}

func (h rsaPublicKey) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	fields := make([]string, 0, 10)
	for _, pair := range h.makePairs() {
		fields = append(fields, pair.Key.(string))
		data[pair.Key.(string)] = pair.Value
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

func (h *rsaPublicKey) Keys() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	keys := make([]string, 0, 10+len(h.privateParams))
	if h.algorithm != nil {
		keys = append(keys, AlgorithmKey)
	}
	if h.e != nil {
		keys = append(keys, RSAEKey)
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
	if h.n != nil {
		keys = append(keys, RSANKey)
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
	for k := range h.privateParams {
		keys = append(keys, k)
	}
	return keys
}

type RSAPrivateKey interface {
	Key
	FromRaw(*rsa.PrivateKey) error
	D() []byte
	DP() []byte
	DQ() []byte
	E() []byte
	N() []byte
	P() []byte
	Q() []byte
	QI() []byte
}

type rsaPrivateKey struct {
	algorithm              *jwa.KeyAlgorithm // https://tools.ietf.org/html/rfc7517#section-4.4
	d                      []byte
	dp                     []byte
	dq                     []byte
	e                      []byte
	keyID                  *string           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyOps                 *KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	keyUsage               *string           // https://tools.ietf.org/html/rfc7517#section-4.2
	n                      []byte
	p                      []byte
	q                      []byte
	qi                     []byte
	x509CertChain          *cert.Chain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string     // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string     // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string     // https://tools.ietf.org/html/rfc7515#section-4.1.5
	privateParams          map[string]interface{}
	mu                     *sync.RWMutex
	dc                     json.DecodeCtx
}

var _ RSAPrivateKey = &rsaPrivateKey{}
var _ Key = &rsaPrivateKey{}

func newRSAPrivateKey() *rsaPrivateKey {
	return &rsaPrivateKey{
		mu:            &sync.RWMutex{},
		privateParams: make(map[string]interface{}),
	}
}

func (h rsaPrivateKey) KeyType() jwa.KeyType {
	return jwa.RSA
}

func (h rsaPrivateKey) IsPrivate() bool {
	return true
}

func (h *rsaPrivateKey) Algorithm() jwa.KeyAlgorithm {
	if h.algorithm != nil {
		return *(h.algorithm)
	}
	return jwa.InvalidKeyAlgorithm("")
}

func (h *rsaPrivateKey) D() []byte {
	return h.d
}

func (h *rsaPrivateKey) DP() []byte {
	return h.dp
}

func (h *rsaPrivateKey) DQ() []byte {
	return h.dq
}

func (h *rsaPrivateKey) E() []byte {
	return h.e
}

func (h *rsaPrivateKey) KeyID() string {
	if h.keyID != nil {
		return *(h.keyID)
	}
	return ""
}

func (h *rsaPrivateKey) KeyOps() KeyOperationList {
	if h.keyOps != nil {
		return *(h.keyOps)
	}
	return nil
}

func (h *rsaPrivateKey) KeyUsage() string {
	if h.keyUsage != nil {
		return *(h.keyUsage)
	}
	return ""
}

func (h *rsaPrivateKey) N() []byte {
	return h.n
}

func (h *rsaPrivateKey) P() []byte {
	return h.p
}

func (h *rsaPrivateKey) Q() []byte {
	return h.q
}

func (h *rsaPrivateKey) QI() []byte {
	return h.qi
}

func (h *rsaPrivateKey) X509CertChain() *cert.Chain {
	return h.x509CertChain
}

func (h *rsaPrivateKey) X509CertThumbprint() string {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint)
	}
	return ""
}

func (h *rsaPrivateKey) X509CertThumbprintS256() string {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256)
	}
	return ""
}

func (h *rsaPrivateKey) X509URL() string {
	if h.x509URL != nil {
		return *(h.x509URL)
	}
	return ""
}

func (h *rsaPrivateKey) makePairs() []*HeaderPair {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var pairs []*HeaderPair
	pairs = append(pairs, &HeaderPair{Key: "kty", Value: jwa.RSA})
	if h.algorithm != nil {
		pairs = append(pairs, &HeaderPair{Key: AlgorithmKey, Value: *(h.algorithm)})
	}
	if h.d != nil {
		pairs = append(pairs, &HeaderPair{Key: RSADKey, Value: h.d})
	}
	if h.dp != nil {
		pairs = append(pairs, &HeaderPair{Key: RSADPKey, Value: h.dp})
	}
	if h.dq != nil {
		pairs = append(pairs, &HeaderPair{Key: RSADQKey, Value: h.dq})
	}
	if h.e != nil {
		pairs = append(pairs, &HeaderPair{Key: RSAEKey, Value: h.e})
	}
	if h.keyID != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyIDKey, Value: *(h.keyID)})
	}
	if h.keyOps != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyOpsKey, Value: *(h.keyOps)})
	}
	if h.keyUsage != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyUsageKey, Value: *(h.keyUsage)})
	}
	if h.n != nil {
		pairs = append(pairs, &HeaderPair{Key: RSANKey, Value: h.n})
	}
	if h.p != nil {
		pairs = append(pairs, &HeaderPair{Key: RSAPKey, Value: h.p})
	}
	if h.q != nil {
		pairs = append(pairs, &HeaderPair{Key: RSAQKey, Value: h.q})
	}
	if h.qi != nil {
		pairs = append(pairs, &HeaderPair{Key: RSAQIKey, Value: h.qi})
	}
	if h.x509CertChain != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertChainKey, Value: h.x509CertChain})
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
	return pairs
}

func (h *rsaPrivateKey) PrivateParams() map[string]interface{} {
	return h.privateParams
}

func (h *rsaPrivateKey) Has(name string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case AlgorithmKey:
		return h.algorithm != nil
	case RSADKey:
		return h.d != nil
	case RSADPKey:
		return h.dp != nil
	case RSADQKey:
		return h.dq != nil
	case RSAEKey:
		return h.e != nil
	case KeyIDKey:
		return h.keyID != nil
	case KeyOpsKey:
		return h.keyOps != nil
	case KeyUsageKey:
		return h.keyUsage != nil
	case RSANKey:
		return h.n != nil
	case RSAPKey:
		return h.p != nil
	case RSAQKey:
		return h.q != nil
	case RSAQIKey:
		return h.qi != nil
	case X509CertChainKey:
		return h.x509CertChain != nil
	case X509CertThumbprintKey:
		return h.x509CertThumbprint != nil
	case X509CertThumbprintS256Key:
		return h.x509CertThumbprintS256 != nil
	case X509URLKey:
		return h.x509URL != nil
	default:
		_, ok := h.privateParams[name]
		return ok
	}
}

func (h *rsaPrivateKey) Get(name string, dst interface{}) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case KeyTypeKey:
		if err := blackmagic.AssignIfCompatible(dst, h.KeyType()); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
	case AlgorithmKey:
		if h.algorithm == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.algorithm)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case RSADKey:
		if h.d == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.d); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case RSADPKey:
		if h.dp == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.dp); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case RSADQKey:
		if h.dq == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.dq); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case RSAEKey:
		if h.e == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.e); err != nil {
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
	case RSANKey:
		if h.n == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.n); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case RSAPKey:
		if h.p == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.p); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case RSAQKey:
		if h.q == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.q); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case RSAQIKey:
		if h.qi == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.qi); err != nil {
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

func (h *rsaPrivateKey) Set(name string, value interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.setNoLock(name, value)
}

func (h *rsaPrivateKey) setNoLock(name string, value interface{}) error {
	switch name {
	case "kty":
		return nil
	case AlgorithmKey:
		switch v := value.(type) {
		case string, jwa.SignatureAlgorithm, jwa.ContentEncryptionAlgorithm:
			var tmp = jwa.KeyAlgorithmFrom(v)
			h.algorithm = &tmp
		case fmt.Stringer:
			s := v.String()
			var tmp = jwa.KeyAlgorithmFrom(s)
			h.algorithm = &tmp
		default:
			return fmt.Errorf(`invalid type for %s key: %T`, AlgorithmKey, value)
		}
		return nil
	case RSADKey:
		if v, ok := value.([]byte); ok {
			h.d = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, RSADKey, value)
	case RSADPKey:
		if v, ok := value.([]byte); ok {
			h.dp = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, RSADPKey, value)
	case RSADQKey:
		if v, ok := value.([]byte); ok {
			h.dq = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, RSADQKey, value)
	case RSAEKey:
		if v, ok := value.([]byte); ok {
			h.e = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, RSAEKey, value)
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
	case RSANKey:
		if v, ok := value.([]byte); ok {
			h.n = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, RSANKey, value)
	case RSAPKey:
		if v, ok := value.([]byte); ok {
			h.p = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, RSAPKey, value)
	case RSAQKey:
		if v, ok := value.([]byte); ok {
			h.q = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, RSAQKey, value)
	case RSAQIKey:
		if v, ok := value.([]byte); ok {
			h.qi = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, RSAQIKey, value)
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
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

func (k *rsaPrivateKey) Remove(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch key {
	case AlgorithmKey:
		k.algorithm = nil
	case RSADKey:
		k.d = nil
	case RSADPKey:
		k.dp = nil
	case RSADQKey:
		k.dq = nil
	case RSAEKey:
		k.e = nil
	case KeyIDKey:
		k.keyID = nil
	case KeyOpsKey:
		k.keyOps = nil
	case KeyUsageKey:
		k.keyUsage = nil
	case RSANKey:
		k.n = nil
	case RSAPKey:
		k.p = nil
	case RSAQKey:
		k.q = nil
	case RSAQIKey:
		k.qi = nil
	case X509CertChainKey:
		k.x509CertChain = nil
	case X509CertThumbprintKey:
		k.x509CertThumbprint = nil
	case X509CertThumbprintS256Key:
		k.x509CertThumbprintS256 = nil
	case X509URLKey:
		k.x509URL = nil
	default:
		delete(k.privateParams, key)
	}
	return nil
}

func (k *rsaPrivateKey) Clone() (Key, error) {
	return cloneKey(k)
}

func (k *rsaPrivateKey) DecodeCtx() json.DecodeCtx {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.dc
}

func (k *rsaPrivateKey) SetDecodeCtx(dc json.DecodeCtx) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dc = dc
}

func (h *rsaPrivateKey) UnmarshalJSON(buf []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.algorithm = nil
	h.d = nil
	h.dp = nil
	h.dq = nil
	h.e = nil
	h.keyID = nil
	h.keyOps = nil
	h.keyUsage = nil
	h.n = nil
	h.p = nil
	h.q = nil
	h.qi = nil
	h.x509CertChain = nil
	h.x509CertThumbprint = nil
	h.x509CertThumbprintS256 = nil
	h.x509URL = nil
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
				if val != jwa.RSA.String() {
					return fmt.Errorf(`invalid kty value for RSAPublicKey (%s)`, val)
				}
			case AlgorithmKey:
				var s string
				if err := dec.Decode(&s); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, AlgorithmKey, err)
				}
				alg := jwa.KeyAlgorithmFrom(s)
				h.algorithm = &alg
			case RSADKey:
				if err := json.AssignNextBytesToken(&h.d, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, RSADKey, err)
				}
			case RSADPKey:
				if err := json.AssignNextBytesToken(&h.dp, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, RSADPKey, err)
				}
			case RSADQKey:
				if err := json.AssignNextBytesToken(&h.dq, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, RSADQKey, err)
				}
			case RSAEKey:
				if err := json.AssignNextBytesToken(&h.e, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, RSAEKey, err)
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
			case RSANKey:
				if err := json.AssignNextBytesToken(&h.n, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, RSANKey, err)
				}
			case RSAPKey:
				if err := json.AssignNextBytesToken(&h.p, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, RSAPKey, err)
				}
			case RSAQKey:
				if err := json.AssignNextBytesToken(&h.q, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, RSAQKey, err)
				}
			case RSAQIKey:
				if err := json.AssignNextBytesToken(&h.qi, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, RSAQIKey, err)
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
	if h.d == nil {
		return fmt.Errorf(`required field d is missing`)
	}
	if h.e == nil {
		return fmt.Errorf(`required field e is missing`)
	}
	if h.n == nil {
		return fmt.Errorf(`required field n is missing`)
	}
	return nil
}

func (h rsaPrivateKey) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	fields := make([]string, 0, 16)
	for _, pair := range h.makePairs() {
		fields = append(fields, pair.Key.(string))
		data[pair.Key.(string)] = pair.Value
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

func (h *rsaPrivateKey) Keys() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	keys := make([]string, 0, 16+len(h.privateParams))
	if h.algorithm != nil {
		keys = append(keys, AlgorithmKey)
	}
	if h.d != nil {
		keys = append(keys, RSADKey)
	}
	if h.dp != nil {
		keys = append(keys, RSADPKey)
	}
	if h.dq != nil {
		keys = append(keys, RSADQKey)
	}
	if h.e != nil {
		keys = append(keys, RSAEKey)
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
	if h.n != nil {
		keys = append(keys, RSANKey)
	}
	if h.p != nil {
		keys = append(keys, RSAPKey)
	}
	if h.q != nil {
		keys = append(keys, RSAQKey)
	}
	if h.qi != nil {
		keys = append(keys, RSAQIKey)
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
	for k := range h.privateParams {
		keys = append(keys, k)
	}
	return keys
}
