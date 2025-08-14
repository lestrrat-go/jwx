//go:build jwx_es256k

package jwsbb

import (
	"crypto"

	dsigsecp256k1 "github.com/lestrrat-go/dsig-secp256k1"
)

func init() {
	const RFC7518Alg = "ES256K"
	// Register mapping for ES256K to dsig algorithm
	_ = RegisterAlgorithm(
		RFC7518Alg,
		AlgorithmInfo{
			Family: ECDSA,
			Dsig:   dsigsecp256k1.ECDSAWithSecp256k1AndSHA256,
			Meta: ECDSAFamilyMeta{
				Hash: crypto.SHA256,
			},
		},
	)
}
