package examples_test

import (
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	// Importing dsig-circl-ed448 for its side effects registers the Ed448
	// algorithm with dsig, making it available to jws.Sign and jws.Verify.
	_ "github.com/lestrrat-go/dsig-circl-ed448"
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
