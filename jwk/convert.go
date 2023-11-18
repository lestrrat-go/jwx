package jwk

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"reflect"
	"sync"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

// # Converting between Raw Keys and `jwk.Key`s
//
// A converter that converts from a raw key to a `jwk.Key` is called a RJKeyConverter.
// A converter that converts from a `jwk.Key` to a raw key is called a JRKeyConverter.
//
// You can register a convert from a raw key to a `jwk.Key` by calling
// `jwk.RegisterRJKeyConverter`.

var rjConverters = make(map[reflect.Type]RJKeyConverter)
var jrConverters = make(map[jwa.KeyType][]JRKeyConverter)

var muRJConverters sync.RWMutex
var muJRConverters sync.RWMutex

func RegisterRJKeyConverter(from interface{}, conv RJKeyConverter) {
	muRJConverters.Lock()
	defer muRJConverters.Unlock()
	rjConverters[reflect.TypeOf(from)] = conv
}

func RegisterJRKeyConverter(kty jwa.KeyType, conv JRKeyConverter) {
	muJRConverters.Lock()
	defer muJRConverters.Unlock()
	convs, ok := jrConverters[kty]
	if !ok {
		convs = []JRKeyConverter{conv}
	} else {
		convs = append([]JRKeyConverter{conv}, convs...)
	}
	jrConverters[kty] = convs
}

type RJKeyConverter interface {
	FromRaw(interface{}) (Key, error)
}

type RJKeyConvertFunc func(interface{}) (Key, error)

func (f RJKeyConvertFunc) FromRaw(raw interface{}) (Key, error) {
	return f(raw)
}

// JRKeyConverter is used to convert from a `jwk.Key` to a raw key.
type JRKeyConverter interface {
	// Raw takes the `jwk.Key` to be converted, and a hint (the raw key to be converted to).
	// The hint is the object that the user requested the result to be assigned to.
	// The method should return the converted raw key, or an error if the conversion fails.
	//
	// Third party modules MUST NOT create raw
	//
	// When the user calls `key.Raw(dst)`, the `dst` object is a _pointer_ to the
	// object that the user wants the result to be assigned to, but the converter
	// receives the _value_ that this pointer points to, to make it easier to
	// detect the type of the result.
	//
	// Note that the the second argument may be an `interface{}` (which means that the
	// user has delegated the type detection to the converter).
	//
	// Raw must NOT modify the hint object, and should return jwk.ContinueError
	// if the hint object is not compatible with the converter.
	Raw(Key, interface{}) (interface{}, error)
}

type JRKeyConvertFunc func(Key, interface{}) (interface{}, error)

func (f JRKeyConvertFunc) Raw(key Key, hint interface{}) (interface{}, error) {
	return f(key, hint)
}

func init() {
	{
		f := RJKeyConvertFunc(rsaPrivateKeyToJWK)
		k := rsa.PrivateKey{}
		RegisterRJKeyConverter(k, f)
		RegisterRJKeyConverter(&k, f)
	}
	{
		f := RJKeyConvertFunc(rsaPublicKeyToJWK)
		k := rsa.PublicKey{}
		RegisterRJKeyConverter(k, f)
		RegisterRJKeyConverter(&k, f)
	}
	{
		f := RJKeyConvertFunc(ecdsaPrivateKeyToJWK)
		k := ecdsa.PrivateKey{}
		RegisterRJKeyConverter(k, f)
		RegisterRJKeyConverter(&k, f)
	}
	{
		f := RJKeyConvertFunc(ecdsaPublicKeyToJWK)
		k := ecdsa.PublicKey{}
		RegisterRJKeyConverter(k, f)
		RegisterRJKeyConverter(&k, f)
	}
	{
		f := RJKeyConvertFunc(okpPrivateKeyToJWK)
		for _, k := range []interface{}{ed25519.PrivateKey(nil), ecdh.PrivateKey{}, &ecdh.PrivateKey{}} {
			RegisterRJKeyConverter(k, f)
		}
	}
	{
		f := RJKeyConvertFunc(okpPublicKeyToJWK)
		for _, k := range []interface{}{ed25519.PublicKey(nil), ecdh.PublicKey{}, &ecdh.PublicKey{}} {
			RegisterRJKeyConverter(k, f)
		}
	}

	RegisterRJKeyConverter([]byte(nil), RJKeyConvertFunc(bytesToKey))
}

// These may seem a bit repetitive and redandunt, but the problem is that
// each key type has its own FromRaw method -- for example, FromRaw(*ecdsa.PrivateKey)
// vs FromRaw(*rsa.PrivateKey), and therefore they can't just be bundled into
// a single function.
func rsaPrivateKeyToJWK(src interface{}) (Key, error) {
	var raw *rsa.PrivateKey
	switch src := src.(type) {
	case *rsa.PrivateKey:
		raw = src
	case rsa.PrivateKey:
		raw = &src
	default:
		return nil, fmt.Errorf(`cannot convert key type '%T' to RSA jwk.Key`, src)
	}
	k := newRSAPrivateKey()
	if err := k.FromRaw(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func rsaPublicKeyToJWK(src interface{}) (Key, error) {
	var raw *rsa.PublicKey
	switch src := src.(type) {
	case *rsa.PublicKey:
		raw = src
	case rsa.PublicKey:
		raw = &src
	default:
		return nil, fmt.Errorf(`cannot convert key type '%T' to RSA jwk.Key`, src)
	}
	k := newRSAPublicKey()
	if err := k.FromRaw(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func ecdsaPrivateKeyToJWK(src interface{}) (Key, error) {
	var raw *ecdsa.PrivateKey
	switch src := src.(type) {
	case *ecdsa.PrivateKey:
		raw = src
	case ecdsa.PrivateKey:
		raw = &src
	default:
		return nil, fmt.Errorf(`cannot convert key type '%T' to ECDSA jwk.Key`, src)
	}
	k := newECDSAPrivateKey()
	if err := k.FromRaw(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func ecdsaPublicKeyToJWK(src interface{}) (Key, error) {
	var raw *ecdsa.PublicKey
	switch src := src.(type) {
	case *ecdsa.PublicKey:
		raw = src
	case ecdsa.PublicKey:
		raw = &src
	default:
		return nil, fmt.Errorf(`cannot convert key type '%T' to ECDSA jwk.Key`, src)
	}
	k := newECDSAPublicKey()
	if err := k.FromRaw(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func okpPrivateKeyToJWK(src interface{}) (Key, error) {
	var raw interface{}
	switch src.(type) {
	case ed25519.PrivateKey, *ecdh.PrivateKey:
		raw = src
	case ecdh.PrivateKey:
		raw = &src
	default:
		return nil, fmt.Errorf(`cannot convert key type '%T' to OKP jwk.Key`, src)
	}
	k := newOKPPrivateKey()
	if err := k.FromRaw(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func okpPublicKeyToJWK(src interface{}) (Key, error) {
	var raw interface{}
	switch src.(type) {
	case ed25519.PublicKey, *ecdh.PublicKey:
		raw = src
	case ecdh.PublicKey:
		raw = &src
	default:
		return nil, fmt.Errorf(`jwk: convert raw to OKP jwk.Key: cannot convert key type '%T' to OKP jwk.Key`, src)
	}
	k := newOKPPublicKey()
	if err := k.FromRaw(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

func bytesToKey(src interface{}) (Key, error) {
	var raw []byte
	switch src := src.(type) {
	case []byte:
		raw = src
	default:
		return nil, fmt.Errorf(`cannot convert key type '%T' to symmetric jwk.Key`, src)
	}

	k := newSymmetricKey()
	if err := k.FromRaw(raw); err != nil {
		return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, raw, err)
	}
	return k, nil
}

// All objects call this method to convert themselves to a raw key.
// It's done this way to centralize the logic (mapping) of which keys are converted
// to what raw key.
func raw(key Key, dst interface{}) error {
	muRJConverters.RLock()
	defer muRJConverters.RUnlock()
	// dst better be a pointer
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Ptr {
		return fmt.Errorf(`destination object must be a pointer`)
	}
	if convs, ok := jrConverters[key.KeyType()]; ok {
		for _, conv := range convs {
			v, err := conv.Raw(key, dst)
			if err != nil {
				if IsContinueError(err) {
					continue
				}
				return fmt.Errorf(`failed to convert jwk.Key to raw format: %w`, err)
			}

			if err := blackmagic.AssignIfCompatible(dst, v); err != nil {
				return fmt.Errorf(`failed to assign key: %w`, err)
			}
			return nil
		}
	}
	return fmt.Errorf(`failed to find converter for key type '%T'`, key)
}
