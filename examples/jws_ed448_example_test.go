package examples_test

import (
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	// Importing the ed448 module registers Ed448 signing, verification,
	// and JWK key import/export. This is all that's needed to enable Ed448.
	_ "github.com/lestrrat-go/jwx-circl-ed448"
)

func Example_jws_sign_verify_ed448() {
	pubkey, privkey, err := ed448.GenerateKey(nil)
	if err != nil {
		fmt.Printf("failed to generate Ed448 key: %s\n", err)
		return
	}

	const payload = "Hello, Ed448!"

	// Sign using the fully-specified Ed448 algorithm (RFC 9864)
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.EdDSAEd448(), privkey))
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	// Verify
	verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd448(), pubkey))
	if err != nil {
		fmt.Printf("failed to verify: %s\n", err)
		return
	}

	fmt.Println(string(verified))
	// OUTPUT:
	// Hello, Ed448!
}
