package ecdsa

import (
	"crypto/elliptic"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

var muCurves sync.RWMutex
var algToCurveMap map[jwa.EllipticCurveAlgorithm]elliptic.Curve
var curveToAlgMap map[elliptic.Curve]jwa.EllipticCurveAlgorithm
var algList []jwa.EllipticCurveAlgorithm

func init() {
	muCurves.Lock()
	algToCurveMap = make(map[jwa.EllipticCurveAlgorithm]elliptic.Curve)
	curveToAlgMap = make(map[elliptic.Curve]jwa.EllipticCurveAlgorithm)
	muCurves.Unlock()
}

// RegisterCurve registers a jwa.EllipticCurveAlgorithm constant and its
// corresponding elliptic.Curve object. Users do not need to call this unless
// they are registering a new ECDSA key type.
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterCurve(alg jwa.EllipticCurveAlgorithm, crv elliptic.Curve) error {
	muCurves.Lock()
	defer muCurves.Unlock()

	algToCurveMap[alg] = crv
	curveToAlgMap[crv] = alg
	rebuildCurves()
	return nil
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

// Algorithms returns the list of registered jwa.EllipticCurveAlgorithms
// that ca be used for ECDSA keys.
func Algorithms() []jwa.EllipticCurveAlgorithm {
	muCurves.RLock()
	defer muCurves.RUnlock()

	return algList
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

	crv, ok := algToCurveMap[alg]
	if !ok {
		return nil, fmt.Errorf(`unknown elliptic curve algorithm: %q`, alg)
	}
	return crv, nil
}

func IsCurveAvailable(alg jwa.EllipticCurveAlgorithm) bool {
	muCurves.RLock()
	defer muCurves.RUnlock()

	_, ok := algToCurveMap[alg]
	return ok
}
