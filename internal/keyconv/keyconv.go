package keyconv

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
	"reflect"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// KeyAs converts src to type T. src may be a jwk.Key or a raw crypto key.
// If src is a jwk.Key, it is exported via jwk.Export[T]. Otherwise, a direct
// type assertion is attempted, with a reflect fallback for value→pointer
// conversion (e.g. rsa.PrivateKey when T = *rsa.PrivateKey).
func KeyAs[T any](src any) (T, error) {
	if jwkKey, ok := src.(jwk.Key); ok {
		return jwk.Export[T](jwkKey)
	}
	if v, ok := src.(T); ok {
		return v, nil
	}
	// value → pointer: e.g. rsa.PrivateKey when T = *rsa.PrivateKey
	var zero T
	target := reflect.TypeFor[T]()
	if src != nil && target.Kind() == reflect.Ptr {
		rv := reflect.ValueOf(src)
		if rv.IsValid() && rv.Type() == target.Elem() {
			ptr := reflect.New(rv.Type())
			ptr.Elem().Set(rv)
			v, ok := ptr.Interface().(T)
			if !ok {
				return zero, fmt.Errorf(`keyconv: expected %T, got %T`, zero, src)
			}
			return v, nil
		}
	}
	return zero, fmt.Errorf(`keyconv: expected %T, got %T`, zero, src)
}

// RSAPublicKey extracts an *rsa.PublicKey from src.
// src may be rsa.PublicKey, *rsa.PublicKey, rsa.PrivateKey, *rsa.PrivateKey, or jwk.Key.
func RSAPublicKey(src any) (*rsa.PublicKey, error) {
	if jwkKey, ok := src.(jwk.Key); ok {
		pk, err := jwk.PublicRawKeyOf(jwkKey)
		if err != nil {
			return nil, fmt.Errorf(`keyconv: failed to produce public key from %T: %w`, src, err)
		}
		src = pk
	}

	switch src := src.(type) {
	case rsa.PrivateKey:
		return &src.PublicKey, nil
	case *rsa.PrivateKey:
		return &src.PublicKey, nil
	case rsa.PublicKey:
		return &src, nil
	case *rsa.PublicKey:
		return src, nil
	default:
		return nil, fmt.Errorf(`keyconv: expected rsa.PublicKey/rsa.PrivateKey or *rsa.PublicKey/*rsa.PrivateKey, got %T`, src)
	}
}

// ECDSAPublicKey extracts an *ecdsa.PublicKey from src.
// src may be ecdsa.PublicKey, *ecdsa.PublicKey, ecdsa.PrivateKey, *ecdsa.PrivateKey, or jwk.Key.
func ECDSAPublicKey(src any) (*ecdsa.PublicKey, error) {
	if jwkKey, ok := src.(jwk.Key); ok {
		pk, err := jwk.PublicRawKeyOf(jwkKey)
		if err != nil {
			return nil, fmt.Errorf(`keyconv: failed to produce public key from %T: %w`, src, err)
		}
		src = pk
	}

	switch src := src.(type) {
	case ecdsa.PrivateKey:
		return &src.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &src.PublicKey, nil
	case ecdsa.PublicKey:
		return &src, nil
	case *ecdsa.PublicKey:
		return src, nil
	default:
		return nil, fmt.Errorf(`keyconv: expected ecdsa.PublicKey/ecdsa.PrivateKey or *ecdsa.PublicKey/*ecdsa.PrivateKey, got %T`, src)
	}
}

func Ed25519PrivateKey(src any) (*ed25519.PrivateKey, error) {
	if jwkKey, ok := src.(jwk.Key); ok {
		rawV, err := jwk.Export[any](jwkKey)
		if err != nil {
			return nil, fmt.Errorf(`keyconv: failed to produce ed25519.PrivateKey from %T: %w`, src, err)
		}
		ptr, ok := rawV.(*ed25519.PrivateKey)
		if !ok {
			// Export may return ed25519.PrivateKey (not pointer)
			if v, ok := rawV.(ed25519.PrivateKey); ok {
				if len(v) != ed25519.PrivateKeySize {
					return nil, fmt.Errorf(`keyconv: invalid ed25519.PrivateKey length %d from export, expected %d`, len(v), ed25519.PrivateKeySize)
				}
				return &v, nil
			}
			return nil, fmt.Errorf(`keyconv: expected ed25519.PrivateKey from export, got %T`, rawV)
		}
		// Guard against a malformed exported key reaching ed25519.PrivateKey.Public(),
		// which slices priv[32:] and panics when the key is not the expected size.
		if ptr == nil || len(*ptr) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf(`keyconv: invalid ed25519.PrivateKey from export, expected length %d`, ed25519.PrivateKeySize)
		}
		return ptr, nil
	}
	switch src := src.(type) {
	case *ed25519.PrivateKey:
		if src == nil || len(*src) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf(`keyconv: invalid ed25519.PrivateKey length, expected %d`, ed25519.PrivateKeySize)
		}
		return src, nil
	case ed25519.PrivateKey:
		if len(src) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf(`keyconv: invalid ed25519.PrivateKey length %d, expected %d`, len(src), ed25519.PrivateKeySize)
		}
		return &src, nil
	default:
		return nil, fmt.Errorf(`keyconv: expected ed25519.PrivateKey or *ed25519.PrivateKey, got %T`, src)
	}
}

func Ed25519PublicKey(src any) (*ed25519.PublicKey, error) {
	if jwkKey, ok := src.(jwk.Key); ok {
		pk, err := jwk.PublicRawKeyOf(jwkKey)
		if err != nil {
			return nil, fmt.Errorf(`keyconv: failed to produce public key from %T: %w`, src, err)
		}
		src = pk
	}

	// Guard against malformed private keys before calling Public(), which
	// slices priv[32:] and panics when the key is not ed25519.PrivateKeySize.
	switch key := src.(type) {
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf(`keyconv: invalid ed25519.PrivateKey length %d, expected %d`, len(key), ed25519.PrivateKeySize)
		}
		src = key.Public()
	case *ed25519.PrivateKey:
		if key == nil || len(*key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf(`keyconv: invalid ed25519.PrivateKey length, expected %d`, ed25519.PrivateKeySize)
		}
		src = key.Public()
	}

	switch src := src.(type) {
	case ed25519.PublicKey:
		if len(src) != ed25519.PublicKeySize {
			return nil, fmt.Errorf(`keyconv: invalid ed25519.PublicKey length %d, expected %d`, len(src), ed25519.PublicKeySize)
		}
		return &src, nil
	case *ed25519.PublicKey:
		if src == nil || len(*src) != ed25519.PublicKeySize {
			return nil, fmt.Errorf(`keyconv: invalid ed25519.PublicKey length, expected %d`, ed25519.PublicKeySize)
		}
		return src, nil
	case *crypto.PublicKey:
		if src == nil {
			return nil, fmt.Errorf(`failed to retrieve ed25519.PublicKey out of nil *crypto.PublicKey`)
		}
		tmp, ok := (*src).(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf(`failed to retrieve ed25519.PublicKey out of *crypto.PublicKey`)
		}
		if len(tmp) != ed25519.PublicKeySize {
			return nil, fmt.Errorf(`keyconv: invalid ed25519.PublicKey length %d, expected %d`, len(tmp), ed25519.PublicKeySize)
		}
		return &tmp, nil
	case crypto.PublicKey:
		tmp, ok := src.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf(`failed to retrieve ed25519.PublicKey out of crypto.PublicKey`)
		}
		return &tmp, nil
	default:
		return nil, fmt.Errorf(`expected ed25519.PublicKey or *ed25519.PublicKey, got %T`, src)
	}
}

type privECDHer interface {
	ECDH() (*ecdh.PrivateKey, error)
}

// ECDHPrivateKey extracts an *ecdh.PrivateKey from src.
// In addition to jwk.Key and direct type matches, it also handles
// types that implement the ECDH() method (e.g. *ecdsa.PrivateKey).
func ECDHPrivateKey(src any) (*ecdh.PrivateKey, error) {
	if jwkKey, ok := src.(jwk.Key); ok {
		return jwk.Export[*ecdh.PrivateKey](jwkKey)
	}
	switch src := src.(type) {
	case *ecdh.PrivateKey:
		return src, nil
	case ecdh.PrivateKey:
		return &src, nil
	case privECDHer:
		return src.ECDH()
	default:
		return nil, fmt.Errorf(`keyconv: expected *ecdh.PrivateKey or ECDH()-capable key, got %T`, src)
	}
}

type pubECDHer interface {
	ECDH() (*ecdh.PublicKey, error)
}

// ECDHPublicKey extracts an *ecdh.PublicKey from src.
// In addition to jwk.Key and direct type matches, it also handles
// types that implement the ECDH() method (e.g. *ecdsa.PublicKey).
func ECDHPublicKey(src any) (*ecdh.PublicKey, error) {
	if jwkKey, ok := src.(jwk.Key); ok {
		return jwk.Export[*ecdh.PublicKey](jwkKey)
	}
	switch src := src.(type) {
	case *ecdh.PublicKey:
		return src, nil
	case ecdh.PublicKey:
		return &src, nil
	case pubECDHer:
		return src.ECDH()
	default:
		return nil, fmt.Errorf(`keyconv: expected *ecdh.PublicKey or ECDH()-capable key, got %T`, src)
	}
}

// ecdhCurveToElliptic maps ECDH curves to elliptic curves
func ecdhCurveToElliptic(ecdhCurve ecdh.Curve) (elliptic.Curve, error) {
	switch ecdhCurve {
	case ecdh.P256():
		return elliptic.P256(), nil
	case ecdh.P384():
		return elliptic.P384(), nil
	case ecdh.P521():
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf(`keyconv: unsupported ECDH curve: %v`, ecdhCurve)
	}
}

// ecdhPublicKeyToECDSA converts an ECDH public key to an ECDSA public key
func ecdhPublicKeyToECDSA(ecdhPubKey *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	curve, err := ecdhCurveToElliptic(ecdhPubKey.Curve())
	if err != nil {
		return nil, err
	}

	pubBytes := ecdhPubKey.Bytes()

	// Parse the uncompressed point format (0x04 prefix + X + Y coordinates)
	if len(pubBytes) == 0 || pubBytes[0] != 0x04 {
		return nil, fmt.Errorf(`keyconv: invalid ECDH public key format`)
	}

	keyLen := (len(pubBytes) - 1) / 2
	if len(pubBytes) != 1+2*keyLen {
		return nil, fmt.Errorf(`keyconv: invalid ECDH public key length`)
	}

	x := new(big.Int).SetBytes(pubBytes[1 : 1+keyLen])
	y := new(big.Int).SetBytes(pubBytes[1+keyLen:])

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// ECDHToECDSA converts an ECDH key to an ECDSA key.
// Returns *ecdsa.PublicKey for public keys, *ecdsa.PrivateKey for private keys.
func ECDHToECDSA(src any) (any, error) {
	// First, handle value types by converting to pointers
	switch s := src.(type) {
	case ecdh.PrivateKey:
		src = &s
	case ecdh.PublicKey:
		src = &s
	}

	var privBytes []byte
	var pubkey *ecdh.PublicKey
	switch src := src.(type) {
	case *ecdh.PrivateKey:
		pubkey = src.PublicKey()
		privBytes = src.Bytes()
	case *ecdh.PublicKey:
		pubkey = src
	default:
		return nil, fmt.Errorf(`keyconv: expected ecdh.PrivateKey, *ecdh.PrivateKey, ecdh.PublicKey, or *ecdh.PublicKey, got %T`, src)
	}

	// convert the public key
	ecdsaPubKey, err := ecdhPublicKeyToECDSA(pubkey)
	if err != nil {
		return nil, fmt.Errorf(`keyconv.ECDHToECDSA: failed to convert ECDH public key to ECDSA public key: %w`, err)
	}

	if privBytes == nil {
		return ecdsaPubKey, nil
	}

	ecdsaPrivKey := &ecdsa.PrivateKey{
		D:         new(big.Int).SetBytes(privBytes),
		PublicKey: *ecdsaPubKey,
	}

	return ecdsaPrivKey, nil
}
