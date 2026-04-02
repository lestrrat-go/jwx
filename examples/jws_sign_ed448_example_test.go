package examples_test

import (
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	// Importing jwx-circl-ed448 for its side effects registers Ed448
	// with jwa, jws, and jwk, making it fully available for JWS operations.
	_ "github.com/lestrrat-go/jwx-circl-ed448"
)

func Example_jws_sign_ed448() {
	pub, priv, err := ed448.GenerateKey(nil)
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	payload := []byte("Hello, Ed448!")

	signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd448(), priv))
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd448(), pub))
	if err != nil {
		fmt.Printf("failed to verify: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// Hello, Ed448!
}
