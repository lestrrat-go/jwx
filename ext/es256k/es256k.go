// Package es256k provides ES256K (secp256k1) support for jwx.
//
// Import this package for its side effects to enable ES256K signing,
// verification, and key management:
//
//	import _ "github.com/jwx-go/es256k"
package es256k

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dsigsecp256k1 "github.com/lestrrat-go/dsig-secp256k1"
	"github.com/lestrrat-go/jwx/v3/jwa"
	ourecdsa "github.com/lestrrat-go/jwx/v3/jwk/ecdsa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

// ES256K returns the ES256K signature algorithm identifier.
func ES256K() jwa.SignatureAlgorithm {
	return jwa.NewSignatureAlgorithm("ES256K")
}

// Secp256k1 returns the secp256k1 elliptic curve algorithm identifier.
func Secp256k1() jwa.EllipticCurveAlgorithm {
	return jwa.NewEllipticCurveAlgorithm("secp256k1")
}

func init() {
	// Register the secp256k1 elliptic curve
	jwa.RegisterEllipticCurveAlgorithm(Secp256k1())

	// Register ES256K signature algorithm
	jwa.RegisterSignatureAlgorithm(ES256K())

	// Register secp256k1 curve for ECDSA key handling
	ourecdsa.RegisterCurve(Secp256k1(), secp256k1.S256())

	// Register ES256K in the algorithm-to-key-type mapping
	jws.RegisterAlgorithmForKeyType(jwa.EC(), ES256K())

	// Register the dsig algorithm mapping for ES256K
	jwsbb.RegisterDsigAlgorithm("ES256K", dsigsecp256k1.ECDSAWithSecp256k1AndSHA256)
}
