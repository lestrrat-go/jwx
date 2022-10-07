// Generated by "sketch" utility. DO NOT EDIT
package jwe

import (
	"bytes"
	"fmt"
	"sort"
	"sync"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/byteslice"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func NewHeaders() Headers {
	return &stdHeaders{}
}

func (v *stdHeaders) DecodeCtx() DecodeCtx {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.dc
}

func (v *stdHeaders) SetDecodeCtx(dc DecodeCtx) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dc = dc
}

func (v *stdHeaders) decodeExtraField(name string, dec *json.Decoder, dst interface{}) error {
	if dc := v.dc; dc != nil {
		if localReg := dc.Registry(); localReg != nil {
			decoded, err := localReg.Decode(dec, name)
			if err == nil {
				if err := blackmagic.AssignIfCompatible(dst, decoded); err != nil {
					return fmt.Errorf(`failed to assign decoded value for %q: %w`, name, err)
				}
				return nil
			}
		}
	}

	decoded, err := registry.Decode(dec, name)
	if err == nil {
		if err := blackmagic.AssignIfCompatible(dst, decoded); err != nil {
			return fmt.Errorf(`failed to assign decoded value for %q: %w`, name, err)
		}
		return nil
	}

	return fmt.Errorf(`failed to decode field %q: %w`, name, err)
}

type stdHeaders struct {
	mu                     sync.RWMutex
	agreementPartyUInfo    *byteslice.Buffer
	agreementPartyVInfo    *byteslice.Buffer
	algorithm              *jwa.KeyEncryptionAlgorithm
	compression            *jwa.CompressionAlgorithm
	contentType            *string
	contentEncryption      *jwa.ContentEncryptionAlgorithm
	critical               []string
	ephemeralPublicKey     jwk.Key
	jwk                    jwk.Key
	jwkSetURL              *string
	keyID                  *string
	typ                    *string
	x509CertChain          *cert.Chain
	x509CertThumbprint     *string
	x509CertThumbprintS256 *string
	x509URL                *string
	dc                     DecodeCtx
	raw                    []uint8
	extra                  map[string]interface{}
}

// These constants are used when the JSON field name is used.
// Their use is not strictly required, but certain linters
// complain about repeated constants, and therefore internally
// this used throughout
const (
	AgreementPartyUInfoKey    = "apu"
	AgreementPartyVInfoKey    = "apv"
	AlgorithmKey              = "alg"
	CompressionKey            = "zip"
	ContentTypeKey            = "cty"
	ContentEncryptionKey      = "enc"
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

// Get retrieves the value associated with a key
func (v *stdHeaders) Get(key string, dst interface{}) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.getNoLock(key, dst, false)
}

// getNoLock is a utility method that is called from Get, MarshalJSON, etc, but
// it can be used from user-supplied code. Unlike Get, it avoids locking for
// each call, so the user needs to explicitly lock the object before using,
// but otherwise should be faster than sing Get directly
func (v *stdHeaders) getNoLock(key string, dst interface{}, raw bool) error {
	switch key {
	case AgreementPartyUInfoKey:
		if val := v.agreementPartyUInfo; val != nil {
			if raw {
				return blackmagic.AssignIfCompatible(dst, val)
			}
			return blackmagic.AssignIfCompatible(dst, val.Bytes())
		}
	case AgreementPartyVInfoKey:
		if val := v.agreementPartyVInfo; val != nil {
			if raw {
				return blackmagic.AssignIfCompatible(dst, val)
			}
			return blackmagic.AssignIfCompatible(dst, val.Bytes())
		}
	case AlgorithmKey:
		if val := v.algorithm; val != nil {
			return blackmagic.AssignIfCompatible(dst, *val)
		}
	case CompressionKey:
		if val := v.compression; val != nil {
			return blackmagic.AssignIfCompatible(dst, *val)
		}
	case ContentTypeKey:
		if val := v.contentType; val != nil {
			return blackmagic.AssignIfCompatible(dst, *val)
		}
	case ContentEncryptionKey:
		if val := v.contentEncryption; val != nil {
			return blackmagic.AssignIfCompatible(dst, *val)
		}
	case CriticalKey:
		if val := v.critical; val != nil {
			return blackmagic.AssignIfCompatible(dst, val)
		}
	case EphemeralPublicKeyKey:
		if val := v.ephemeralPublicKey; val != nil {
			return blackmagic.AssignIfCompatible(dst, val)
		}
	case JWKKey:
		if val := v.jwk; val != nil {
			return blackmagic.AssignIfCompatible(dst, val)
		}
	case JWKSetURLKey:
		if val := v.jwkSetURL; val != nil {
			return blackmagic.AssignIfCompatible(dst, *val)
		}
	case KeyIDKey:
		if val := v.keyID; val != nil {
			return blackmagic.AssignIfCompatible(dst, *val)
		}
	case TypeKey:
		if val := v.typ; val != nil {
			return blackmagic.AssignIfCompatible(dst, *val)
		}
	case X509CertChainKey:
		if val := v.x509CertChain; val != nil {
			return blackmagic.AssignIfCompatible(dst, val)
		}
	case X509CertThumbprintKey:
		if val := v.x509CertThumbprint; val != nil {
			return blackmagic.AssignIfCompatible(dst, *val)
		}
	case X509CertThumbprintS256Key:
		if val := v.x509CertThumbprintS256; val != nil {
			return blackmagic.AssignIfCompatible(dst, *val)
		}
	case X509URLKey:
		if val := v.x509URL; val != nil {
			return blackmagic.AssignIfCompatible(dst, *val)
		}
	default:
		if v.extra != nil {
			val, ok := v.extra[key]
			if ok {
				return blackmagic.AssignIfCompatible(dst, val)
			}
		}
	}
	return fmt.Errorf(`no such key %q`, key)
}

// Set sets the value of the specified field. The name must be a JSON
// field name, not the Go name
func (v *stdHeaders) Set(key string, value interface{}) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch key {
	case AgreementPartyUInfoKey:
		var object byteslice.Buffer
		if err := object.AcceptValue(value); err != nil {
			return fmt.Errorf(`failed to accept value: %w`, err)
		}
		v.agreementPartyUInfo = &object
	case AgreementPartyVInfoKey:
		var object byteslice.Buffer
		if err := object.AcceptValue(value); err != nil {
			return fmt.Errorf(`failed to accept value: %w`, err)
		}
		v.agreementPartyVInfo = &object
	case AlgorithmKey:
		converted, ok := value.(jwa.KeyEncryptionAlgorithm)
		if !ok {
			return fmt.Errorf(`expected value of type jwa.KeyEncryptionAlgorithm for field alg, got %T`, value)
		}
		v.algorithm = &converted
	case CompressionKey:
		converted, ok := value.(jwa.CompressionAlgorithm)
		if !ok {
			return fmt.Errorf(`expected value of type jwa.CompressionAlgorithm for field zip, got %T`, value)
		}
		v.compression = &converted
	case ContentTypeKey:
		converted, ok := value.(string)
		if !ok {
			return fmt.Errorf(`expected value of type string for field cty, got %T`, value)
		}
		v.contentType = &converted
	case ContentEncryptionKey:
		converted, ok := value.(jwa.ContentEncryptionAlgorithm)
		if !ok {
			return fmt.Errorf(`expected value of type jwa.ContentEncryptionAlgorithm for field enc, got %T`, value)
		}
		v.contentEncryption = &converted
	case CriticalKey:
		converted, ok := value.([]string)
		if !ok {
			return fmt.Errorf(`expected value of type []string for field crit, got %T`, value)
		}
		v.critical = converted
	case EphemeralPublicKeyKey:
		converted, ok := value.(jwk.Key)
		if !ok {
			return fmt.Errorf(`expected value of type jwk.Key for field epk, got %T`, value)
		}
		v.ephemeralPublicKey = converted
	case JWKKey:
		converted, ok := value.(jwk.Key)
		if !ok {
			return fmt.Errorf(`expected value of type jwk.Key for field jwk, got %T`, value)
		}
		v.jwk = converted
	case JWKSetURLKey:
		converted, ok := value.(string)
		if !ok {
			return fmt.Errorf(`expected value of type string for field jku, got %T`, value)
		}
		v.jwkSetURL = &converted
	case KeyIDKey:
		converted, ok := value.(string)
		if !ok {
			return fmt.Errorf(`expected value of type string for field kid, got %T`, value)
		}
		v.keyID = &converted
	case TypeKey:
		converted, ok := value.(string)
		if !ok {
			return fmt.Errorf(`expected value of type string for field typ, got %T`, value)
		}
		v.typ = &converted
	case X509CertChainKey:
		converted, ok := value.(*cert.Chain)
		if !ok {
			return fmt.Errorf(`expected value of type *cert.Chain for field x5c, got %T`, value)
		}
		v.x509CertChain = converted
	case X509CertThumbprintKey:
		converted, ok := value.(string)
		if !ok {
			return fmt.Errorf(`expected value of type string for field x5t, got %T`, value)
		}
		v.x509CertThumbprint = &converted
	case X509CertThumbprintS256Key:
		converted, ok := value.(string)
		if !ok {
			return fmt.Errorf(`expected value of type string for field x5t#S256, got %T`, value)
		}
		v.x509CertThumbprintS256 = &converted
	case X509URLKey:
		converted, ok := value.(string)
		if !ok {
			return fmt.Errorf(`expected value of type string for field x5u, got %T`, value)
		}
		v.x509URL = &converted
	default:
		if v.extra == nil {
			v.extra = make(map[string]interface{})
		}

		v.extra[key] = value
	}
	return nil
}

// Has returns true if the field specified by the argument has been populated.
// The field name must be the JSON field name, not the Go-structure's field name.
func (v *stdHeaders) Has(name string) bool {
	switch name {
	case AgreementPartyUInfoKey:
		return v.agreementPartyUInfo != nil
	case AgreementPartyVInfoKey:
		return v.agreementPartyVInfo != nil
	case AlgorithmKey:
		return v.algorithm != nil
	case CompressionKey:
		return v.compression != nil
	case ContentTypeKey:
		return v.contentType != nil
	case ContentEncryptionKey:
		return v.contentEncryption != nil
	case CriticalKey:
		return v.critical != nil
	case EphemeralPublicKeyKey:
		return v.ephemeralPublicKey != nil
	case JWKKey:
		return v.jwk != nil
	case JWKSetURLKey:
		return v.jwkSetURL != nil
	case KeyIDKey:
		return v.keyID != nil
	case TypeKey:
		return v.typ != nil
	case X509CertChainKey:
		return v.x509CertChain != nil
	case X509CertThumbprintKey:
		return v.x509CertThumbprint != nil
	case X509CertThumbprintS256Key:
		return v.x509CertThumbprintS256 != nil
	case X509URLKey:
		return v.x509URL != nil
	default:
		if v.extra != nil {
			if _, ok := v.extra[name]; ok {
				return true
			}
		}
		return false
	}
}

// Keys returns a slice of string comprising of JSON field names whose values
// are present in the object.
func (v *stdHeaders) Keys() []string {
	keys := make([]string, 0, 18)
	if v.agreementPartyUInfo != nil {
		keys = append(keys, AgreementPartyUInfoKey)
	}
	if v.agreementPartyVInfo != nil {
		keys = append(keys, AgreementPartyVInfoKey)
	}
	if v.algorithm != nil {
		keys = append(keys, AlgorithmKey)
	}
	if v.compression != nil {
		keys = append(keys, CompressionKey)
	}
	if v.contentType != nil {
		keys = append(keys, ContentTypeKey)
	}
	if v.contentEncryption != nil {
		keys = append(keys, ContentEncryptionKey)
	}
	if v.critical != nil {
		keys = append(keys, CriticalKey)
	}
	if v.ephemeralPublicKey != nil {
		keys = append(keys, EphemeralPublicKeyKey)
	}
	if v.jwk != nil {
		keys = append(keys, JWKKey)
	}
	if v.jwkSetURL != nil {
		keys = append(keys, JWKSetURLKey)
	}
	if v.keyID != nil {
		keys = append(keys, KeyIDKey)
	}
	if v.typ != nil {
		keys = append(keys, TypeKey)
	}
	if v.x509CertChain != nil {
		keys = append(keys, X509CertChainKey)
	}
	if v.x509CertThumbprint != nil {
		keys = append(keys, X509CertThumbprintKey)
	}
	if v.x509CertThumbprintS256 != nil {
		keys = append(keys, X509CertThumbprintS256Key)
	}
	if v.x509URL != nil {
		keys = append(keys, X509URLKey)
	}

	if len(v.extra) > 0 {
		for k := range v.extra {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// HasAgreementPartyUInfo returns true if the field `apu` has been populated
func (v *stdHeaders) HasAgreementPartyUInfo() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.agreementPartyUInfo != nil
}

// HasAgreementPartyVInfo returns true if the field `apv` has been populated
func (v *stdHeaders) HasAgreementPartyVInfo() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.agreementPartyVInfo != nil
}

// HasAlgorithm returns true if the field `alg` has been populated
func (v *stdHeaders) HasAlgorithm() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.algorithm != nil
}

// HasCompression returns true if the field `zip` has been populated
func (v *stdHeaders) HasCompression() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.compression != nil
}

// HasContentType returns true if the field `cty` has been populated
func (v *stdHeaders) HasContentType() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.contentType != nil
}

// HasContentEncryption returns true if the field `enc` has been populated
func (v *stdHeaders) HasContentEncryption() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.contentEncryption != nil
}

// HasCritical returns true if the field `crit` has been populated
func (v *stdHeaders) HasCritical() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.critical != nil
}

// HasEphemeralPublicKey returns true if the field `epk` has been populated
func (v *stdHeaders) HasEphemeralPublicKey() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.ephemeralPublicKey != nil
}

// HasJWK returns true if the field `jwk` has been populated
func (v *stdHeaders) HasJWK() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.jwk != nil
}

// HasJWKSetURL returns true if the field `jku` has been populated
func (v *stdHeaders) HasJWKSetURL() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.jwkSetURL != nil
}

// HasKeyID returns true if the field `kid` has been populated
func (v *stdHeaders) HasKeyID() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keyID != nil
}

// HasType returns true if the field `typ` has been populated
func (v *stdHeaders) HasType() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.typ != nil
}

// HasX509CertChain returns true if the field `x5c` has been populated
func (v *stdHeaders) HasX509CertChain() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.x509CertChain != nil
}

// HasX509CertThumbprint returns true if the field `x5t` has been populated
func (v *stdHeaders) HasX509CertThumbprint() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.x509CertThumbprint != nil
}

// HasX509CertThumbprintS256 returns true if the field `x5t#S256` has been populated
func (v *stdHeaders) HasX509CertThumbprintS256() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.x509CertThumbprintS256 != nil
}

// HasX509URL returns true if the field `x5u` has been populated
func (v *stdHeaders) HasX509URL() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.x509URL != nil
}

func (v *stdHeaders) AgreementPartyUInfo() []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.agreementPartyUInfo; val != nil {
		return val.Bytes()
	}
	return []byte(nil)
}

func (v *stdHeaders) AgreementPartyVInfo() []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.agreementPartyVInfo; val != nil {
		return val.Bytes()
	}
	return []byte(nil)
}

func (v *stdHeaders) Algorithm() jwa.KeyEncryptionAlgorithm {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.algorithm; val != nil {
		return *val
	}
	return jwa.KeyEncryptionAlgorithm("")
}

func (v *stdHeaders) Compression() jwa.CompressionAlgorithm {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.compression; val != nil {
		return *val
	}
	return jwa.NoCompress
}

func (v *stdHeaders) ContentType() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.contentType; val != nil {
		return *val
	}
	return ""
}

func (v *stdHeaders) ContentEncryption() jwa.ContentEncryptionAlgorithm {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.contentEncryption; val != nil {
		return *val
	}
	return jwa.ContentEncryptionAlgorithm("")
}

func (v *stdHeaders) Critical() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.critical; val != nil {
		return val
	}
	return []string(nil)
}

func (v *stdHeaders) EphemeralPublicKey() jwk.Key {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.ephemeralPublicKey; val != nil {
		return val
	}
	return nil
}

func (v *stdHeaders) JWK() jwk.Key {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.jwk; val != nil {
		return val
	}
	return nil
}

func (v *stdHeaders) JWKSetURL() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.jwkSetURL; val != nil {
		return *val
	}
	return ""
}

func (v *stdHeaders) KeyID() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.keyID; val != nil {
		return *val
	}
	return ""
}

func (v *stdHeaders) Type() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.typ; val != nil {
		return *val
	}
	return ""
}

func (v *stdHeaders) X509CertChain() *cert.Chain {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.x509CertChain; val != nil {
		return val
	}
	return nil
}

func (v *stdHeaders) X509CertThumbprint() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.x509CertThumbprint; val != nil {
		return *val
	}
	return ""
}

func (v *stdHeaders) X509CertThumbprintS256() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.x509CertThumbprintS256; val != nil {
		return *val
	}
	return ""
}

func (v *stdHeaders) X509URL() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if val := v.x509URL; val != nil {
		return *val
	}
	return ""
}

// Remove removes the value associated with a key
func (v *stdHeaders) Remove(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	switch key {
	case AgreementPartyUInfoKey:
		v.agreementPartyUInfo = nil
	case AgreementPartyVInfoKey:
		v.agreementPartyVInfo = nil
	case AlgorithmKey:
		v.algorithm = nil
	case CompressionKey:
		v.compression = nil
	case ContentTypeKey:
		v.contentType = nil
	case ContentEncryptionKey:
		v.contentEncryption = nil
	case CriticalKey:
		v.critical = nil
	case EphemeralPublicKeyKey:
		v.ephemeralPublicKey = nil
	case JWKKey:
		v.jwk = nil
	case JWKSetURLKey:
		v.jwkSetURL = nil
	case KeyIDKey:
		v.keyID = nil
	case TypeKey:
		v.typ = nil
	case X509CertChainKey:
		v.x509CertChain = nil
	case X509CertThumbprintKey:
		v.x509CertThumbprint = nil
	case X509CertThumbprintS256Key:
		v.x509CertThumbprintS256 = nil
	case X509URLKey:
		v.x509URL = nil
	default:
		delete(v.extra, key)
	}

	return nil
}

func (v *stdHeaders) Clone(dst interface{}) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var extra map[string]interface{}
	if len(v.extra) > 0 {
		extra = make(map[string]interface{})
		for key, val := range v.extra {
			extra[key] = val
		}
	}
	return blackmagic.AssignIfCompatible(dst, &stdHeaders{
		agreementPartyUInfo:    v.agreementPartyUInfo,
		agreementPartyVInfo:    v.agreementPartyVInfo,
		algorithm:              v.algorithm,
		compression:            v.compression,
		contentType:            v.contentType,
		contentEncryption:      v.contentEncryption,
		critical:               v.critical,
		ephemeralPublicKey:     v.ephemeralPublicKey,
		jwk:                    v.jwk,
		jwkSetURL:              v.jwkSetURL,
		keyID:                  v.keyID,
		typ:                    v.typ,
		x509CertChain:          v.x509CertChain,
		x509CertThumbprint:     v.x509CertThumbprint,
		x509CertThumbprintS256: v.x509CertThumbprintS256,
		x509URL:                v.x509URL,
		dc:                     v.dc,
		raw:                    v.raw,
		extra:                  extra,
	})
}

// MarshalJSON serializes stdHeaders into JSON.
// All pre-declared fields are included as long as a value is
// assigned to them, as well as all extra fields. All of these
// fields are sorted in alphabetical order.
func (v *stdHeaders) MarshalJSON() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	buf.WriteByte('{')
	for i, k := range v.Keys() {
		var val interface{}
		if err := v.getNoLock(k, &val, true); err != nil {
			return nil, fmt.Errorf(`failed to retrieve value for field %q: %w`, k, err)
		}

		if i > 0 {
			buf.WriteByte(',')
		}
		if err := enc.Encode(k); err != nil {
			return nil, fmt.Errorf(`failed to encode map key name: %w`, err)
		}
		buf.WriteByte(':')
		if err := enc.Encode(val); err != nil {
			return nil, fmt.Errorf(`failed to encode map value for %q: %w`, k, err)
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON deserializes a piece of JSON data into stdHeaders.
//
// Pre-defined fields must be deserializable via "encoding/json" to their
// respective Go types, otherwise an error is returned.
//
// Extra fields are stored in a special "extra" storage, which can only
// be accessed via `Get()` and `Set()` methods.
func (v *stdHeaders) UnmarshalJSON(data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.agreementPartyUInfo = nil
	v.agreementPartyVInfo = nil
	v.algorithm = nil
	v.compression = nil
	v.contentType = nil
	v.contentEncryption = nil
	v.critical = nil
	v.ephemeralPublicKey = nil
	v.jwk = nil
	v.jwkSetURL = nil
	v.keyID = nil
	v.typ = nil
	v.x509CertChain = nil
	v.x509CertThumbprint = nil
	v.x509CertThumbprintS256 = nil
	v.x509URL = nil

	dec := json.NewDecoder(bytes.NewReader(data))
	var extra map[string]interface{}

LOOP:
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf(`error reading JSON token: %w`, err)
		}
		switch tok := tok.(type) {
		case json.Delim:
			if tok == '}' { // end of object
				break LOOP
			}
			// we should only get into this clause at the very beginning, and just once
			if tok != '{' {
				return fmt.Errorf(`expected '{', but got '%c'`, tok)
			}
		case string:
			switch tok {
			case AgreementPartyUInfoKey:
				var acceptValue interface{}
				if err := dec.Decode(&acceptValue); err != nil {
					return fmt.Errorf(`failed to decode vlaue for %q: %w`, AgreementPartyUInfoKey, err)
				}
				var val byteslice.Buffer
				err = val.AcceptValue(acceptValue)
				if err != nil {
					return fmt.Errorf(`failed to accept value for %q: %w`, AgreementPartyUInfoKey, err)
				}
				v.agreementPartyUInfo = &val
			case AgreementPartyVInfoKey:
				var acceptValue interface{}
				if err := dec.Decode(&acceptValue); err != nil {
					return fmt.Errorf(`failed to decode vlaue for %q: %w`, AgreementPartyVInfoKey, err)
				}
				var val byteslice.Buffer
				err = val.AcceptValue(acceptValue)
				if err != nil {
					return fmt.Errorf(`failed to accept value for %q: %w`, AgreementPartyVInfoKey, err)
				}
				v.agreementPartyVInfo = &val
			case AlgorithmKey:
				var val jwa.KeyEncryptionAlgorithm
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, AlgorithmKey, err)
				}
				v.algorithm = &val
			case CompressionKey:
				var val jwa.CompressionAlgorithm
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, CompressionKey, err)
				}
				v.compression = &val
			case ContentTypeKey:
				var val string
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, ContentTypeKey, err)
				}
				v.contentType = &val
			case ContentEncryptionKey:
				var val jwa.ContentEncryptionAlgorithm
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, ContentEncryptionKey, err)
				}
				v.contentEncryption = &val
			case CriticalKey:
				var val []string
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, CriticalKey, err)
				}
				v.critical = val
			case EphemeralPublicKeyKey:
				var ifaceSrc json.RawMessage
				if err := dec.Decode(&ifaceSrc); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, EphemeralPublicKeyKey, err)
				}
				val, err := jwk.ParseKey(ifaceSrc)
				if err != nil {
					return fmt.Errorf(`failed to decode interface value for %q: %w`, EphemeralPublicKeyKey, err)
				}
				v.ephemeralPublicKey = val
			case JWKKey:
				var ifaceSrc json.RawMessage
				if err := dec.Decode(&ifaceSrc); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, JWKKey, err)
				}
				val, err := jwk.ParseKey(ifaceSrc)
				if err != nil {
					return fmt.Errorf(`failed to decode interface value for %q: %w`, JWKKey, err)
				}
				v.jwk = val
			case JWKSetURLKey:
				var val string
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, JWKSetURLKey, err)
				}
				v.jwkSetURL = &val
			case KeyIDKey:
				var val string
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, KeyIDKey, err)
				}
				v.keyID = &val
			case TypeKey:
				var val string
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, TypeKey, err)
				}
				v.typ = &val
			case X509CertChainKey:
				var val cert.Chain
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, X509CertChainKey, err)
				}
				v.x509CertChain = &val
			case X509CertThumbprintKey:
				var val string
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, X509CertThumbprintKey, err)
				}
				v.x509CertThumbprint = &val
			case X509CertThumbprintS256Key:
				var val string
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, X509CertThumbprintS256Key, err)
				}
				v.x509CertThumbprintS256 = &val
			case X509URLKey:
				var val string
				if err := dec.Decode(&val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, X509URLKey, err)
				}
				v.x509URL = &val
			default:
				var val interface{}
				if err := v.decodeExtraField(tok, dec, &val); err != nil {
					return fmt.Errorf(`failed to decode value for %q: %w`, tok, err)
				}
				if extra == nil {
					extra = make(map[string]interface{})
				}
				extra[tok] = val
			}
		}
	}

	if extra != nil {
		v.extra = extra
	}
	return nil
}
