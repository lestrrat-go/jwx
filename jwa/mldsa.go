//go:build go1.27

package jwa

import "fmt"

// ML-DSA (FIPS 204) signature algorithm names, as they appear in the JWS
// "alg" header. These match the names crypto/mldsa's Parameters.String()
// returns, and the names used by the JOSE registration in RFC 9881.
const (
	mldsa44 = "ML-DSA-44"
	mldsa65 = "ML-DSA-65"
	mldsa87 = "ML-DSA-87"
)

// ML-DSA is registered here rather than in objects.yml because the algorithms
// exist only when the toolchain provides crypto/mldsa, which lands in Go 1.27.
// Advertising them on Go 1.26 would let LookupSignatureAlgorithm succeed for an
// algorithm that no signer or verifier can service.
func init() {
	algorithms := []SignatureAlgorithm{
		NewSignatureAlgorithm(mldsa44),
		NewSignatureAlgorithm(mldsa65),
		NewSignatureAlgorithm(mldsa87),
	}
	if err := RegisterSignatureAlgorithm(algorithms...); err != nil {
		panic(fmt.Sprintf("jwa: failed to register builtin ML-DSA SignatureAlgorithm: %s", err))
	}
	for _, alg := range algorithms {
		markBuiltin(alg.String())
	}
}

// MLDSA44 returns an object representing the ML-DSA-44 signature algorithm
// (FIPS 204, NIST security level 2).
//
// This algorithm is available only when jwx is built with Go 1.27 or later,
// which is when crypto/mldsa becomes part of the standard library.
func MLDSA44() SignatureAlgorithm {
	return lookupBuiltinSignatureAlgorithm(mldsa44)
}

// MLDSA65 returns an object representing the ML-DSA-65 signature algorithm
// (FIPS 204, NIST security level 3).
//
// This algorithm is available only when jwx is built with Go 1.27 or later,
// which is when crypto/mldsa becomes part of the standard library.
func MLDSA65() SignatureAlgorithm {
	return lookupBuiltinSignatureAlgorithm(mldsa65)
}

// MLDSA87 returns an object representing the ML-DSA-87 signature algorithm
// (FIPS 204, NIST security level 5).
//
// This algorithm is available only when jwx is built with Go 1.27 or later,
// which is when crypto/mldsa becomes part of the standard library.
func MLDSA87() SignatureAlgorithm {
	return lookupBuiltinSignatureAlgorithm(mldsa87)
}
