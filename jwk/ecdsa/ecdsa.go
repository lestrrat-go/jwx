package ecdsa

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

// PointValidator validates whether (x, y) represents a safe-to-use
// public key point on the associated elliptic curve. Implementations
// MUST reject:
//
//   - the identity point (0, 0)
//   - any point that is not on the curve
//   - any other coordinate pair that would lead to an unsafe key
//     (for example, small-subgroup points where applicable)
//
// ValidatePoint returns nil iff the point is safe to use. jwk consults
// the registered PointValidator on every parse, import, and Validate()
// call that touches an ECDSA key, so it is the choke point that
// protects downstream crypto/ecdsa and crypto/ecdh consumers from
// invalid-curve attacks.
//
// jwk guarantees that x and y fit in the curve's field (BitLen() is at
// most crv.Params().BitSize) before invoking ValidatePoint. Validators
// that write coordinates into a fixed-size buffer via big.Int.FillBytes
// can rely on this precondition.
//
// Extension modules that register a non-stdlib curve (for example
// secp256k1 via jwx-go/es256k) MUST provide a correct PointValidator;
// it is the mechanism that replaces the deprecated
// crypto/elliptic.Curve.IsOnCurve fallback jwk previously used. A
// typical implementation calls the curve library's own point-on-curve
// check after rejecting the identity point explicitly.
//
// For implementations that are naturally a plain function, wrap them
// in PointValidatorFunc instead of defining a new named type.
type PointValidator interface {
	ValidatePoint(x, y *big.Int) error
}

// PointValidatorFunc is a function adapter that lets a plain function
// satisfy the PointValidator interface, analogous to http.HandlerFunc
// for http.Handler.
type PointValidatorFunc func(x, y *big.Int) error

// ValidatePoint calls f(x, y).
func (f PointValidatorFunc) ValidatePoint(x, y *big.Int) error {
	return f(x, y)
}

type curveInfo struct {
	curve     elliptic.Curve
	validator PointValidator
}

var muCurves sync.RWMutex
var algToCurveMap map[jwa.EllipticCurveAlgorithm]curveInfo
var curveToAlgMap map[elliptic.Curve]jwa.EllipticCurveAlgorithm
var algList []jwa.EllipticCurveAlgorithm

func init() {
	muCurves.Lock()
	algToCurveMap = make(map[jwa.EllipticCurveAlgorithm]curveInfo)
	curveToAlgMap = make(map[elliptic.Curve]jwa.EllipticCurveAlgorithm)
	muCurves.Unlock()
}

// RegisterCurve registers a jwa.EllipticCurveAlgorithm constant, its
// corresponding elliptic.Curve object, and a PointValidator that checks
// public-key coordinates on that curve. Users do not need to call this
// unless they are registering a new ECDSA key type from an extension
// module.
//
// The validator must not be nil. jwk uses the registered validator in
// place of calling crypto/elliptic.Curve.IsOnCurve (deprecated in
// Go 1.21) so that custom curves can plug in their own, non-deprecated
// point-membership check. Passing a nil validator returns an error and
// does not register the curve.
//
// RegisterCurve refuses to re-register an alg or curve that is already
// in the registry. This is a deliberate defense-in-depth measure: the
// stdlib NIST P-curves are registered from jwk's init() with
// ecdh-backed validators, and silently allowing a later init() in a
// compromised dependency to overwrite that entry with a weaker or
// no-op validator would disable JWK-003 point validation without any
// observable symptom. Callers that genuinely need to replace an entry
// must unregister it first; this package does not expose an
// unregister API, which keeps the built-in NIST entries effectively
// sealed once jwk is imported.
func RegisterCurve(alg jwa.EllipticCurveAlgorithm, crv elliptic.Curve, validator PointValidator) error {
	if validator == nil {
		return fmt.Errorf(`jwk/ecdsa: RegisterCurve: validator must not be nil`)
	}

	muCurves.Lock()
	defer muCurves.Unlock()

	if _, exists := algToCurveMap[alg]; exists {
		return fmt.Errorf(`jwk/ecdsa: RegisterCurve: algorithm %q is already registered`, alg)
	}
	if _, exists := curveToAlgMap[crv]; exists {
		return fmt.Errorf(`jwk/ecdsa: RegisterCurve: curve %q is already registered`, crv.Params().Name)
	}

	algToCurveMap[alg] = curveInfo{curve: crv, validator: validator}
	curveToAlgMap[crv] = alg
	rebuildCurves()
	return nil
}

// ValidatorFromCurve returns the PointValidator that was registered
// alongside the given curve via RegisterCurve. It returns an error if
// no curve is registered for the given alg.
func ValidatorFromCurve(alg jwa.EllipticCurveAlgorithm) (PointValidator, error) {
	muCurves.RLock()
	defer muCurves.RUnlock()

	info, ok := algToCurveMap[alg]
	if !ok {
		return nil, fmt.Errorf(`unknown elliptic curve algorithm: %q`, alg)
	}
	return info.validator, nil
}

func rebuildCurves() {
	l := len(algToCurveMap)
	if cap(algList) < l {
		algList = make([]jwa.EllipticCurveAlgorithm, 0, l)
	} else {
		algList = algList[:0]
	}

	for alg := range algToCurveMap {
		algList = append(algList, alg)
	}
}

// Algorithms returns a snapshot of the registered
// jwa.EllipticCurveAlgorithms that can be used for ECDSA keys.
//
// The returned slice is caller-owned. Modifying it does not affect the
// package registry, and ordering is unspecified.
func Algorithms() []jwa.EllipticCurveAlgorithm {
	muCurves.RLock()
	defer muCurves.RUnlock()

	return append([]jwa.EllipticCurveAlgorithm(nil), algList...)
}

func AlgorithmFromCurve(crv elliptic.Curve) (jwa.EllipticCurveAlgorithm, error) {
	muCurves.RLock()
	defer muCurves.RUnlock()

	alg, ok := curveToAlgMap[crv]
	if !ok {
		return jwa.InvalidEllipticCurve(), fmt.Errorf(`unknown elliptic curve: %q`, crv)
	}
	return alg, nil
}

func CurveFromAlgorithm(alg jwa.EllipticCurveAlgorithm) (elliptic.Curve, error) {
	muCurves.RLock()
	defer muCurves.RUnlock()

	info, ok := algToCurveMap[alg]
	if !ok {
		return nil, fmt.Errorf(`unknown elliptic curve algorithm: %q`, alg)
	}
	return info.curve, nil
}

func IsCurveAvailable(alg jwa.EllipticCurveAlgorithm) bool {
	muCurves.RLock()
	defer muCurves.RUnlock()

	_, ok := algToCurveMap[alg]
	return ok
}
