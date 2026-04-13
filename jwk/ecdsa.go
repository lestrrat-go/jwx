package jwk

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"reflect"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/ecutil"
	"github.com/lestrrat-go/jwx/v4/jwa"
	ourecdsa "github.com/lestrrat-go/jwx/v4/jwk/ecdsa"
)

func init() {
	panicOnRegistrationError(ourecdsa.RegisterCurve(jwa.P256(), elliptic.P256()))
	panicOnRegistrationError(ourecdsa.RegisterCurve(jwa.P384(), elliptic.P384()))
	panicOnRegistrationError(ourecdsa.RegisterCurve(jwa.P521(), elliptic.P521()))

	panicOnRegistrationError(RegisterKeyExporter(KeyKind(jwa.EC().String()), KeyExportFunc(ecdsaJWKToRaw)))
}

func (k *ecdsaPublicKey) Import(rawKey *ecdsa.PublicKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if rawKey.X == nil {
		return fmt.Errorf(`invalid ecdsa.PublicKey`)
	}

	if rawKey.Y == nil {
		return fmt.Errorf(`invalid ecdsa.PublicKey`)
	}

	xbuf := ecutil.AllocECPointBuffer(rawKey.X, rawKey.Curve)
	ybuf := ecutil.AllocECPointBuffer(rawKey.Y, rawKey.Curve)
	defer ecutil.ReleaseECPointBuffer(xbuf)
	defer ecutil.ReleaseECPointBuffer(ybuf)

	k.x = make([]byte, len(xbuf))
	copy(k.x, xbuf)
	k.y = make([]byte, len(ybuf))
	copy(k.y, ybuf)

	alg, err := ourecdsa.AlgorithmFromCurve(rawKey.Curve)
	if err != nil {
		return fmt.Errorf(`jwk: failed to get algorithm for converting ECDSA public key to JWK: %w`, err)
	}
	k.crv = &alg

	return nil
}

func (k *ecdsaPrivateKey) Import(rawKey *ecdsa.PrivateKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if rawKey.PublicKey.X == nil {
		return fmt.Errorf(`invalid ecdsa.PrivateKey`)
	}
	if rawKey.PublicKey.Y == nil {
		return fmt.Errorf(`invalid ecdsa.PrivateKey`)
	}
	if rawKey.D == nil {
		return fmt.Errorf(`invalid ecdsa.PrivateKey`)
	}

	xbuf := ecutil.AllocECPointBuffer(rawKey.PublicKey.X, rawKey.Curve)
	ybuf := ecutil.AllocECPointBuffer(rawKey.PublicKey.Y, rawKey.Curve)
	dbuf := ecutil.AllocECPointBuffer(rawKey.D, rawKey.Curve)
	defer ecutil.ReleaseECPointBuffer(xbuf)
	defer ecutil.ReleaseECPointBuffer(ybuf)
	defer ecutil.ReleaseECPointBuffer(dbuf)

	k.x = make([]byte, len(xbuf))
	copy(k.x, xbuf)
	k.y = make([]byte, len(ybuf))
	copy(k.y, ybuf)
	k.d = make([]byte, len(dbuf))
	copy(k.d, dbuf)

	alg, err := ourecdsa.AlgorithmFromCurve(rawKey.Curve)
	if err != nil {
		return fmt.Errorf(`jwk: failed to get algorithm for converting ECDSA private key to JWK: %w`, err)
	}
	k.crv = &alg

	return nil
}

func buildECDSAPublicKey(alg jwa.EllipticCurveAlgorithm, xbuf, ybuf []byte) (*ecdsa.PublicKey, error) {
	crv, err := ourecdsa.CurveFromAlgorithm(alg)
	if err != nil {
		return nil, fmt.Errorf(`jwk: failed to get algorithm for ECDSA public key: %w`, err)
	}

	var x, y big.Int
	x.SetBytes(xbuf)
	y.SetBytes(ybuf)

	return &ecdsa.PublicKey{Curve: crv, X: &x, Y: &y}, nil
}

func buildECDHPublicKey(alg jwa.EllipticCurveAlgorithm, xbuf, ybuf []byte) (*ecdh.PublicKey, error) {
	var ecdhcrv ecdh.Curve
	switch alg {
	case jwa.X25519():
		ecdhcrv = ecdh.X25519()
	case jwa.P256():
		ecdhcrv = ecdh.P256()
	case jwa.P384():
		ecdhcrv = ecdh.P384()
	case jwa.P521():
		ecdhcrv = ecdh.P521()
	default:
		return nil, fmt.Errorf(`jwk: unsupported ECDH curve %s`, alg)
	}

	buf := make([]byte, 1+len(xbuf)+len(ybuf))
	buf[0] = 0x04
	copy(buf[1:], xbuf)
	copy(buf[1+len(xbuf):], ybuf)
	return ecdhcrv.NewPublicKey(buf)
}

func buildECDHPrivateKey(alg jwa.EllipticCurveAlgorithm, dbuf []byte) (*ecdh.PrivateKey, error) {
	var ecdhcrv ecdh.Curve
	switch alg {
	case jwa.X25519():
		ecdhcrv = ecdh.X25519()
	case jwa.P256():
		ecdhcrv = ecdh.P256()
	case jwa.P384():
		ecdhcrv = ecdh.P384()
	case jwa.P521():
		ecdhcrv = ecdh.P521()
	default:
		return nil, fmt.Errorf(`jwk: unsupported ECDH curve %s`, alg)
	}

	return ecdhcrv.NewPrivateKey(dbuf)
}

var ecdsaConvertibleTypes = []reflect.Type{
	reflect.TypeFor[ECDSAPrivateKey](),
	reflect.TypeFor[ECDSAPublicKey](),
}

func ecdsaJWKToRaw(keyif Key, hint any) (any, error) {
	var isECDH bool
	switch hint.(type) {
	case nil, ecdsa.PrivateKey, *ecdsa.PrivateKey, ecdsa.PublicKey, *ecdsa.PublicKey:
		// default: return ECDSA format
	case ecdh.PrivateKey, *ecdh.PrivateKey, ecdh.PublicKey, *ecdh.PublicKey:
		isECDH = true
	}

	// Fast path: built-in concrete types need no reflection
	switch keyif.(type) {
	case *ecdsaPrivateKey, *ecdsaPublicKey:
		// already a concrete type, skip extractEmbeddedKey
	default:
		extracted, err := extractEmbeddedKey(keyif, ecdsaConvertibleTypes)
		if err != nil {
			return nil, fmt.Errorf(`jwk: failed to extract embedded key: %w`, err)
		}
		keyif = extracted
	}

	switch k := keyif.(type) {
	case ECDSAPrivateKey:
		var crv jwa.EllipticCurveAlgorithm
		var hasCrv bool
		var od, ox, oy []byte
		locker, ok := k.(rlocker)
		if ok {
			locker.rlock()
			concrete := k.(*ecdsaPrivateKey) //nolint:forcetypeassert // rlocker is unexported; only our concrete types implement it
			if concrete.crv != nil {
				crv = *(concrete.crv)
				hasCrv = true
			}
			od, ox, oy = concrete.d, concrete.x, concrete.y
			locker.runlock()
		} else {
			// External implementation — use self-locking interface getters.
			var ok bool
			if crv, ok = k.Crv(); !ok {
				return nil, fmt.Errorf(`missing "crv" field`)
			}
			hasCrv = true
			if od, ok = k.D(); !ok {
				return nil, fmt.Errorf(`missing "d" field`)
			}
			if ox, ok = k.X(); !ok {
				return nil, fmt.Errorf(`missing "x" field`)
			}
			if oy, ok = k.Y(); !ok {
				return nil, fmt.Errorf(`missing "y" field`)
			}
		}

		if !hasCrv {
			return nil, fmt.Errorf(`missing "crv" field`)
		}

		if isECDH {
			if od == nil {
				return nil, fmt.Errorf(`missing "d" field`)
			}
			return buildECDHPrivateKey(crv, od)
		}

		if ox == nil {
			return nil, fmt.Errorf(`missing "x" field`)
		}
		if oy == nil {
			return nil, fmt.Errorf(`missing "y" field`)
		}
		if od == nil {
			return nil, fmt.Errorf(`missing "d" field`)
		}

		pubk, err := buildECDSAPublicKey(crv, ox, oy)
		if err != nil {
			return nil, fmt.Errorf(`failed to build public key: %w`, err)
		}

		var key ecdsa.PrivateKey
		var d big.Int

		d.SetBytes(od)
		key.D = &d
		key.PublicKey = *pubk

		return &key, nil
	case ECDSAPublicKey:
		var crv jwa.EllipticCurveAlgorithm
		var hasCrv bool
		var x, y []byte
		locker, ok := k.(rlocker)
		if ok {
			locker.rlock()
			concrete := k.(*ecdsaPublicKey) //nolint:forcetypeassert // rlocker is unexported; only our concrete types implement it
			if concrete.crv != nil {
				crv = *(concrete.crv)
				hasCrv = true
			}
			x, y = concrete.x, concrete.y
			locker.runlock()
		} else {
			var ok bool
			if crv, ok = k.Crv(); !ok {
				return nil, fmt.Errorf(`missing "crv" field`)
			}
			hasCrv = true
			if x, ok = k.X(); !ok {
				return nil, fmt.Errorf(`missing "x" field`)
			}
			if y, ok = k.Y(); !ok {
				return nil, fmt.Errorf(`missing "y" field`)
			}
		}

		if !hasCrv {
			return nil, fmt.Errorf(`missing "crv" field`)
		}
		if x == nil {
			return nil, fmt.Errorf(`missing "x" field`)
		}
		if y == nil {
			return nil, fmt.Errorf(`missing "y" field`)
		}
		if isECDH {
			return buildECDHPublicKey(crv, x, y)
		}
		return buildECDSAPublicKey(crv, x, y)
	default:
		return nil, ContinueError()
	}
}

func makeECDSAPublicKey(src Key) (Key, error) {
	newKey := newECDSAPublicKey()

	// Iterate and copy everything except for the bits that should not be in the public key
	for _, k := range src.Keys() {
		switch k {
		case ECDSADKey:
			continue
		default:
			v, ok := src.Field(k)
			if !ok {
				return nil, fmt.Errorf(`ecdsa: makeECDSAPublicKey: failed to get field %q`, k)
			}
			if err := newKey.Set(k, v); err != nil {
				return nil, fmt.Errorf(`ecdsa: makeECDSAPublicKey: failed to set field %q: %w`, k, err)
			}
		}
	}

	return newKey, nil
}

func (k *ecdsaPrivateKey) PublicKey() (Key, error) {
	return makeECDSAPublicKey(k)
}

func (k *ecdsaPublicKey) PublicKey() (Key, error) {
	return makeECDSAPublicKey(k)
}

func ecdsaThumbprint(hash crypto.Hash, crv, x, y string) []byte {
	h := hash.New()
	fmt.Fprint(h, `{"crv":"`)
	fmt.Fprint(h, crv)
	fmt.Fprint(h, `","kty":"EC","x":"`)
	fmt.Fprint(h, x)
	fmt.Fprint(h, `","y":"`)
	fmt.Fprint(h, y)
	fmt.Fprint(h, `"}`)
	return h.Sum(nil)
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k *ecdsaPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	key, err := Export[*ecdsa.PublicKey](k)
	if err != nil {
		return nil, fmt.Errorf(`failed to export ecdsa.PublicKey for thumbprint generation: %w`, err)
	}

	xbuf := ecutil.AllocECPointBuffer(key.X, key.Curve)
	ybuf := ecutil.AllocECPointBuffer(key.Y, key.Curve)
	defer ecutil.ReleaseECPointBuffer(xbuf)
	defer ecutil.ReleaseECPointBuffer(ybuf)

	return ecdsaThumbprint(
		hash,
		key.Curve.Params().Name,
		base64.EncodeToString(xbuf),
		base64.EncodeToString(ybuf),
	), nil
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k *ecdsaPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	key, err := Export[*ecdsa.PrivateKey](k)
	if err != nil {
		return nil, fmt.Errorf(`failed to export ecdsa.PrivateKey for thumbprint generation: %w`, err)
	}

	xbuf := ecutil.AllocECPointBuffer(key.X, key.Curve)
	ybuf := ecutil.AllocECPointBuffer(key.Y, key.Curve)
	defer ecutil.ReleaseECPointBuffer(xbuf)
	defer ecutil.ReleaseECPointBuffer(ybuf)

	return ecdsaThumbprint(
		hash,
		key.Curve.Params().Name,
		base64.EncodeToString(xbuf),
		base64.EncodeToString(ybuf),
	), nil
}

func ecdsaValidateKey(k interface {
	Crv() (jwa.EllipticCurveAlgorithm, bool)
	X() ([]byte, bool)
	Y() ([]byte, bool)
}, checkPrivate bool) error {
	crvtyp, ok := k.Crv()
	if !ok {
		return fmt.Errorf(`missing "crv" field`)
	}

	crv, err := ourecdsa.CurveFromAlgorithm(crvtyp)
	if err != nil {
		return fmt.Errorf(`invalid curve algorithm %q: %w`, crvtyp, err)
	}

	keySize := ecutil.CalculateKeySize(crv)
	if x, ok := k.X(); !ok || len(x) != keySize {
		return fmt.Errorf(`invalid "x" length (%d) for curve %q`, len(x), crv.Params().Name)
	}

	if y, ok := k.Y(); !ok || len(y) != keySize {
		return fmt.Errorf(`invalid "y" length (%d) for curve %q`, len(y), crv.Params().Name)
	}

	if checkPrivate {
		if priv, ok := k.(keyWithD); ok {
			if d, ok := priv.D(); !ok || len(d) != keySize {
				return fmt.Errorf(`invalid "d" length (%d) for curve %q`, len(d), crv.Params().Name)
			}
		} else {
			return fmt.Errorf(`missing "d" value`)
		}
	}
	return nil
}

func (k *ecdsaPrivateKey) Validate() error {
	if err := ecdsaValidateKey(k, true); err != nil {
		return NewKeyValidationError(fmt.Errorf(`jwk.ECDSAPrivateKey: %w`, err))
	}
	return nil
}

func (k *ecdsaPublicKey) Validate() error {
	if err := ecdsaValidateKey(k, false); err != nil {
		return NewKeyValidationError(fmt.Errorf(`jwk.ECDSAPublicKey: %w`, err))
	}
	return nil
}
