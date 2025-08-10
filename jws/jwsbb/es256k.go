package jwsbb

import (
	"crypto"

	dsigsecp256k1 "github.com/lestrrat-go/dsig-secp256k1"
)

func init() {
	const RFC7518Alg = "ES256K"
	// Register mapping for ES256K to dsig algorithm
	RegisterDsigAlgorithm(RFC7518Alg, dsigsecp256k1.ECDSAWithSecp256k1AndSHA256)

	// Register ES256K to use crypto.SHA256
	RegisterECDSAHashFunc(RFC7518Alg, crypto.SHA256)

}
