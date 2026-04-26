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
	panicOnRegistrationError(ourecdsa.RegisterCurve(jwa.P256(), elliptic.P256(), ecdhPointValidator(ecdh.P256(), 32)))
	panicOnRegistrationError(ourecdsa.RegisterCurve(jwa.P384(), elliptic.P384(), ecdhPointValidator(ecdh.P384(), 48)))
	panicOnRegistrationError(ourecdsa.RegisterCurve(jwa.P521(), elliptic.P521(), ecdhPointValidator(ecdh.P521(), 66)))

	panicOnRegistrationError(RegisterKeyExporter(KeyKind(jwa.EC().String()), KeyExportFunc(ecdsaJWKToRaw)))
}

// ecdhPointValidator returns a PointValidator for a stdlib NIST curve
// that routes validation through crypto/ecdh. Go 1.21 deprecated the
// generic crypto/elliptic.Curve methods in favor of crypto/ecdh for
// exactly this use case: ecdh.Curve.NewPublicKey parses the SEC1
// uncompressed encoding (0x04 || X || Y), enforces point-on-curve
// membership, and rejects the identity point as a side effect. Routing
// the stdlib curves through ecdh means jwk never touches any
// deprecated crypto/elliptic method for the curves the Go team
// explicitly wanted callers to migrate.
//
// size is the fixed byte length of each coordinate on the curve
// (32 for P-256, 48 for P-384, 66 for P-521). It is supplied literally
// rather than computed from crv.Params().BitSize so that a mismatched
// registration is caught at code-review time, not at runtime.
func ecdhPointValidator(crv ecdh.Curve, size int) ourecdsa.PointValidator {
	return ourecdsa.PointValidatorFunc(func(x, y *big.Int) error {
		buf := make([]byte, 1+2*size)
		buf[0] = 0x04
		x.FillBytes(buf[1 : 1+size])
		y.FillBytes(buf[1+size:])
		if _, err := crv.NewPublicKey(buf); err != nil {
			return fmt.Errorf(`invalid ECDSA public key: %w`, err)
		}
		return nil
	})
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

	if err := validateECDSAPoint(rawKey.Curve, rawKey.X, rawKey.Y); err != nil {
		return fmt.Errorf(`jwk: %w`, err)
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

	if err := validateECDSAPoint(rawKey.Curve, rawKey.PublicKey.X, rawKey.PublicKey.Y); err != nil {
		return fmt.Errorf(`jwk: %w`, err)
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

	if err := validateECDSAPoint(crv, &x, &y); err != nil {
		return nil, fmt.Errorf(`jwk: %w`, err)
	}

	return &ecdsa.PublicKey{Curve: crv, X: &x, Y: &y}, nil
}

// validateECDSAPoint rejects ECDSA public key coordinates that are not
// safe to use: the identity point (0, 0) and any point that does not lie
// on the named curve. Without these checks, attacker-supplied JWKs can
// smuggle off-curve or small-subgroup points into downstream ECDSA/ECDH
// operations (invalid-curve attacks). See JWK-003.
//
// The identity-point check is done inline here so every caller gets it
// unconditionally. The on-curve check is delegated to the PointValidator
// that was registered alongside the curve via jwk/ecdsa.RegisterCurve:
// the stdlib NIST P-curves register an ecdh-backed validator from this
// package's init(); extension modules such as jwx-go/es256k register
// their own curve-library-backed validators.
//
// Delegating via a registered validator keeps jwk completely free of
// calls to the crypto/elliptic.Curve methods that Go 1.21 deprecated.
// Each curve's validator lives next to the code that knows how to
// validate it correctly — ecdh.Curve.NewPublicKey for stdlib curves,
// the third-party library's own point check for custom curves — and
// jwk never has to fall back to an IsOnCurve call on the deprecated
// interface.
//
// A curve with no registered validator is treated as an error: it is
// the extension module author's responsibility to supply one, and
// failing closed is preferable to silently accepting unvalidated
// points.
func validateECDSAPoint(crv elliptic.Curve, x, y *big.Int) error {
	if x.Sign() == 0 && y.Sign() == 0 {
		return fmt.Errorf(`invalid ECDSA public key: identity point is not a valid public key`)
	}

	// Coordinates must fit in the curve's field. PointValidator
	// implementations commonly write x and y into a fixed-size buffer
	// (jwk's own ecdhPointValidator uses big.Int.FillBytes; third-party
	// validators registered via jwk/ecdsa.RegisterCurve, e.g. secp256k1
	// in jwx-go/es256k, follow the same pattern). FillBytes panics on
	// oversized input. Bounding here makes the PointValidator contract
	// safe by construction for every registered curve, including any
	// custom curve a downstream extension may add.
	bits := crv.Params().BitSize
	if x.BitLen() > bits {
		return fmt.Errorf(`invalid ECDSA public key: x coordinate is %d bits, exceeds curve %q field size of %d bits`, x.BitLen(), crv.Params().Name, bits)
	}
	if y.BitLen() > bits {
		return fmt.Errorf(`invalid ECDSA public key: y coordinate is %d bits, exceeds curve %q field size of %d bits`, y.BitLen(), crv.Params().Name, bits)
	}

	alg, err := ourecdsa.AlgorithmFromCurve(crv)
	if err != nil {
		return fmt.Errorf(`invalid ECDSA public key: %w`, err)
	}
	validator, err := ourecdsa.ValidatorFromCurve(alg)
	if err != nil {
		return fmt.Errorf(`invalid ECDSA public key: %w`, err)
	}
	return validator.ValidatePoint(x, y)
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
	xbuf, ok := k.X()
	if !ok || len(xbuf) != keySize {
		return fmt.Errorf(`invalid "x" length (%d) for curve %q`, len(xbuf), crv.Params().Name)
	}

	ybuf, ok := k.Y()
	if !ok || len(ybuf) != keySize {
		return fmt.Errorf(`invalid "y" length (%d) for curve %q`, len(ybuf), crv.Params().Name)
	}

	var x, y big.Int
	x.SetBytes(xbuf)
	y.SetBytes(ybuf)
	if err := validateECDSAPoint(crv, &x, &y); err != nil {
		return err
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
