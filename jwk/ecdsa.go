package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/ecutil"
	"github.com/lestrrat-go/jwx/v3/jwa"
	ourecdsa "github.com/lestrrat-go/jwx/v3/jwk/ecdsa"
)

func init() {
	ourecdsa.RegisterCurve(jwa.P256, elliptic.P256())
	ourecdsa.RegisterCurve(jwa.P384, elliptic.P384())
	ourecdsa.RegisterCurve(jwa.P521, elliptic.P521())

	RegisterJRKeyConverter(jwa.EC, JRKeyConvertFunc(ecdsaPrivateJWKToRaw))
}

func (k *ecdsaPublicKey) FromRaw(rawKey *ecdsa.PublicKey) error {
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

func (k *ecdsaPrivateKey) FromRaw(rawKey *ecdsa.PrivateKey) error {
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

// Raw returns the EC-DSA public key represented by this JWK
func (k *ecdsaPublicKey) Raw(v interface{}) error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	pubk, err := buildECDSAPublicKey(k.Crv(), k.x, k.y)
	if err != nil {
		return fmt.Errorf(`failed to build public key: %w`, err)
	}

	return blackmagic.AssignIfCompatible(v, pubk)
}

func (k *ecdsaPrivateKey) Raw(v interface{}) error {
	return raw(k, v)
}

func ecdsaPrivateJWKToRaw(keyif Key, hint interface{}) (interface{}, error) {
	switch k := keyif.(type) {
	case *ecdsaPublicKey:
		switch hint.(type) {
		case ecdsa.PublicKey, *ecdsa.PublicKey, interface{}:
		default:
			return nil, fmt.Errorf(`invalid destination object type %T: %w`, hint, ContinueError())
		}

		k.mu.RLock()
		defer k.mu.RUnlock()

		return buildECDSAPublicKey(k.Crv(), k.x, k.y)
	case *ecdsaPrivateKey:
		switch hint.(type) {
		case ecdsa.PrivateKey, *ecdsa.PrivateKey, interface{}:
		default:
			return nil, fmt.Errorf(`invalid destination object type %T: %w`, hint, ContinueError())
		}

		k.mu.RLock()
		defer k.mu.RUnlock()

		pubk, err := buildECDSAPublicKey(k.Crv(), k.x, k.y)
		if err != nil {
			return nil, fmt.Errorf(`failed to build public key: %w`, err)
		}

		var key ecdsa.PrivateKey
		var d big.Int
		d.SetBytes(k.d)
		key.D = &d
		key.PublicKey = *pubk

		return &key, nil
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
			var v interface{}
			if err := src.Get(k, &v); err != nil {
				return nil, fmt.Errorf(`ecdsa: makeECDSAPublicKey: failed to get field %q: %w`, k, err)
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
func (k ecdsaPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	var key ecdsa.PublicKey
	if err := k.Raw(&key); err != nil {
		return nil, fmt.Errorf(`failed to materialize ecdsa.PublicKey for thumbprint generation: %w`, err)
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
func (k ecdsaPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	var key ecdsa.PrivateKey
	if err := k.Raw(&key); err != nil {
		return nil, fmt.Errorf(`failed to materialize ecdsa.PrivateKey for thumbprint generation: %w`, err)
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
	Crv() jwa.EllipticCurveAlgorithm
	X() []byte
	Y() []byte
}, checkPrivate bool) error {
	crv, err := ourecdsa.CurveFromAlgorithm(k.Crv())
	if err != nil {
		return fmt.Errorf(`invalid curve algorithm %q: %w`, k.Crv(), err)
	}

	keySize := ecutil.CalculateKeySize(crv)
	if x := k.X(); len(x) != keySize {
		return fmt.Errorf(`invalid "x" length (%d) for curve %q`, len(x), crv.Params().Name)
	}

	if y := k.Y(); len(y) != keySize {
		return fmt.Errorf(`invalid "y" length (%d) for curve %q`, len(y), crv.Params().Name)
	}

	if checkPrivate {
		if priv, ok := k.(interface{ D() []byte }); ok {
			if len(priv.D()) != keySize {
				return fmt.Errorf(`invalid "d" length (%d) for curve %q`, len(priv.D()), crv.Params().Name)
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
