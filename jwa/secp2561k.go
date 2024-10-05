//go:build jwx_es256k
// +build jwx_es256k

package jwa

// This constant is only available if compiled with jwx_es256k build tag
func Secp256k1() EllipticCurveAlgorithm {
	return lookupEllipticCurveAlgorithm("secp256k1")
}

func init() {
	RegisterEllipticCurveAlgorithm(NewEllipticCurveAlgorithm("secp256k1"))
}
