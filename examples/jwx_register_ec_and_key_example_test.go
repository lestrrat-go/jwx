package examples_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	ourecdsa "github.com/lestrrat-go/jwx/v3/jwk/ecdsa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// Setup. This is something that you probably should do in your adapter
// library, or in your application's init() function.

// I could not readily find what the exact curve notation is for ShangMi SM2
// (either I'm just bad at researching or it's not in an RFC as of this writing)
// so I'm faking it as "SM2".
//
// For demonstration purposes, it could as well be a random string, as long
// as its consistent in your usage.
const SM2 jwa.EllipticCurveAlgorithm = "SM2"

func init() {
	shangmi2pk, _ := sm2.GenerateKey(rand.Reader)

	// Register the algorithm name so it can be looked up
	jwa.RegisterEllipticCurveAlgorithm(SM2)

	// Register the actual ECDSA curve. Notice that we need to tell this
	// to our jwk library, so that the JWK lookup can be done properly
	// when a raw SM2 key is passed to various key operations.
	ourecdsa.RegisterCurve(SM2, sm2.P256())

	// We only need one converter for the private key, because the public key
	// is exactly the same type as *ecdsa.PublicKey
	jwk.RegisterRJKeyConverter(shangmi2pk, jwk.RJKeyConvertFunc(convertShangMiSm2))

	jwk.RegisterJRKeyConverter(jwa.EC, jwk.JRKeyConvertFunc(convertJWKToShangMiSm2))
}

func convertShangMiSm2(key interface{}) (jwk.Key, error) {
	shangmi2pk, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid SM2 private key")
	}
	return jwk.FromRaw(shangmi2pk.PrivateKey)
}

func convertJWKToShangMiSm2(key jwk.Key, hint interface{}) (interface{}, error) {
	ecdsaKey := key.(jwk.ECDSAPrivateKey)
	if ecdsaKey.Crv() != SM2 {
		return nil, fmt.Errorf(`cannot convert curve of type %s to ShangMi key: %w`, ecdsaKey.Crv(), jwk.ContinueError())
	}

	switch hint.(type) {
	case *sm2.PrivateKey, *interface{}:
	default:
		return nil, fmt.Errorf(`can only convert SM2 key to *sm2.PrivateKey (got %T): %w`, hint, jwk.ContinueError())
	}

	var ret sm2.PrivateKey
	ret.PublicKey.Curve = sm2.P256()
	ret.D = (&big.Int{}).SetBytes(ecdsaKey.D())
	ret.PublicKey.X = (&big.Int{}).SetBytes(ecdsaKey.X())
	ret.PublicKey.Y = (&big.Int{}).SetBytes(ecdsaKey.Y())
	return &ret, nil
}

// End setup

func ExampleShangMiSm2() {
	shangmi2pk, _ := sm2.GenerateKey(rand.Reader)

	// Create a jwk.Key from ShangMi SM2 private key
	shangmi2JWK, err := jwk.FromRaw(shangmi2pk)
	if err != nil {
		fmt.Printf("failed to create jwk.Key from raw ShangMi private key: %s\n", err)
		return
	}

	{
		// Create a ShangMi SM2 private key back from the jwk.Key
		var clone sm2.PrivateKey
		if err := shangmi2JWK.Raw(&clone); err != nil {
			fmt.Printf("failed to create ShangMi private key from jwk.Key: %s\n", err)
			return
		}

		// Clone should have same Crv, D, X, and Y values
		if clone.Curve != shangmi2pk.Curve {
			fmt.Println("curve does not match")
			return
		}

		if clone.D.Cmp(shangmi2pk.D) != 0 {
			fmt.Println("D does not match")
			return
		}

		if clone.X.Cmp(shangmi2pk.X) != 0 {
			fmt.Println("X does not match")
			return
		}

		if clone.Y.Cmp(shangmi2pk.Y) != 0 {
			fmt.Println("Y does not match")
			return
		}
	}

	{ // Can do the same thing for interface{}
		var clone interface{}
		if err := shangmi2JWK.Raw(&clone); err != nil {
			fmt.Printf("failed to create ShangMi private key from jwk.Key (via interface{}): %s\n", err)
			return
		}
	}

	{
		// Of course, ecdsa.PrivateKeys are also supported separately
		ecprivkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println(err)
			return
		}
		eckjwk, err := jwk.FromRaw(ecprivkey)
		if err != nil {
			fmt.Printf("failed to create jwk.Key from raw ShangMi public key: %s\n", err)
			return
		}
		var clone ecdsa.PrivateKey
		if err := eckjwk.Raw(&clone); err != nil {
			fmt.Printf("failed to create ShangMi public key from jwk.Key: %s\n", err)
			return
		}
	}

	payload := []byte("Lorem ipsum")
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, shangmi2JWK))
	if err != nil {
		fmt.Printf("Failed to sign using ShangMi key: %s\n", err)
		return
	}

	shangmi2PubJWK, err := jwk.PublicKeyOf(shangmi2JWK)
	if err != nil {
		fmt.Printf("Failed to create public JWK using ShangMi key: %s\n", err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwa.ES256, shangmi2PubJWK))
	if err != nil {
		fmt.Printf("Failed to verify using ShangMi key: %s\n", err)
		return
	}

	if !bytes.Equal(payload, verified) {
		fmt.Println("payload does not match")
		return
	}
	//OUTPUT:
}
