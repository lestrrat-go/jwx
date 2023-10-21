package jwk

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"reflect"
	"sync"
)

// # Converting Raw Keys To `jwk.Key`s
//
// You can register a convert from a raw key to a `jwk.Key` by calling
// `jwk.RegisterKeyConverter`.
//

var keyConverters = make(map[reflect.Type]KeyConverter)

var muKeyConverters sync.RWMutex

func RegisterKeyConverter(from interface{}, conv KeyConverter) {
	muKeyConverters.Lock()
	defer muKeyConverters.Unlock()
	keyConverters[reflect.TypeOf(from)] = conv
}

type KeyConverter interface {
	FromRaw(interface{}) (Key, error)
}

type KeyConvertFunc func(interface{}) (Key, error)

func (f KeyConvertFunc) FromRaw(raw interface{}) (Key, error) {
	return f(raw)
}

func init() {
	{
		f := KeyConvertFunc(rsaPrivateKeyToJWK)
		k := rsa.PrivateKey{}
		RegisterKeyConverter(k, f)
		RegisterKeyConverter(&k, f)
	}
	{
		f := KeyConvertFunc(rsaPublicKeyToJWK)
		k := rsa.PublicKey{}
		RegisterKeyConverter(k, f)
		RegisterKeyConverter(&k, f)
	}
	{
		f := KeyConvertFunc(ecdsaPrivateKeyToJWK)
		k := ecdsa.PrivateKey{}
		RegisterKeyConverter(k, f)
		RegisterKeyConverter(&k, f)
	}
	{
		f := KeyConvertFunc(ecdsaPublicKeyToJWK)
		k := ecdsa.PublicKey{}
		RegisterKeyConverter(k, f)
		RegisterKeyConverter(&k, f)
	}
	{
		f := KeyConvertFunc(okpPrivateKeyToJWK)
		for _, k := range []interface{}{ed25519.PrivateKey(nil), ecdh.PrivateKey{}, &ecdh.PrivateKey{}} {
			RegisterKeyConverter(k, f)
		}
	}
	{
		f := KeyConvertFunc(okpPublicKeyToJWK)
		for _, k := range []interface{}{ed25519.PublicKey(nil), ecdh.PublicKey{}, &ecdh.PublicKey{}} {
			RegisterKeyConverter(k, f)
		}
	}

	RegisterKeyConverter([]byte(nil), KeyConvertFunc(bytesToKey))
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
