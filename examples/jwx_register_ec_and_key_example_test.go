package examples_test

import (
	"bytes"
	"crypto/rand"
	"fmt"

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
	jwk.RegisterKeyConverter(shangmi2pk, jwk.KeyConvertFunc(convertShangMiSm2))
}

func convertShangMiSm2(key interface{}) (jwk.Key, error) {
	shangmi2pk, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid SM2 private key")
	}
	return jwk.FromRaw(shangmi2pk.PrivateKey)
}

// End setup

func ExampleShangMiSm2() {
	shangmi2pk, _ := sm2.GenerateKey(rand.Reader)

	// Create a jwk.Key from ShangMi SM2 private key
	shangmi2JWK, err := jwk.FromRaw(shangmi2pk)
	if err != nil {
		fmt.Println(err)
		return
	}

	{
		// Create a ShangMi SM2 private key back from the jwk.Key
		var clone sm2.PrivateKey
		if err := shangmi2JWK.Raw(&clone); err != nil {
			fmt.Println(err)
			return
		}
	}

	payload := []byte("Lorem ipsum")
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, shangmi2JWK))
	if err != nil {
		fmt.Println(err)
		return
	}

	shangmi2PubJWK, err := jwk.PublicKeyOf(shangmi2JWK)
	if err != nil {
		fmt.Println(err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwa.ES256, shangmi2PubJWK))
	if err != nil {
		fmt.Println(err)
		return
	}

	if !bytes.Equal(payload, verified) {
		fmt.Println("payload does not match")
		return
	}
	//OUTPUT:
}
