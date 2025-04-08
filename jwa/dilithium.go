//go:build jwx_dilithium
// +build jwx_dilithium

package jwa

func init() {
	for _, alg := range []string{"CRYDI2", "CRYDI3", "CRYDI5"} {
		RegisterSignatureAlgorithm(NewSignatureAlgorithm(alg))
	}
}

// CRYDI2 signature algorithm
func CRYDI2() SignatureAlgorithm {
	return lookupBuiltinSignatureAlgorithm("CRYDI2")
}

// CRYDI3 signature algorithm
func CRYDI3() SignatureAlgorithm {
	return lookupBuiltinSignatureAlgorithm("CRYDI3")
}

// CRYDI5 signature algorithm
func CRYDI5() SignatureAlgorithm {
	return lookupBuiltinSignatureAlgorithm("CRYDI5")
}
