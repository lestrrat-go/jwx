package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func Example_jwk_key_specific_metehods() {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate RSA private key: %s\n", err)
		return
	}

	// Use the concrete type parameter to get the typed key directly,
	// instead of importing as jwk.Key and then type-asserting.
	rsakey, err := jwk.Import[jwk.RSAPrivateKey](raw)
	if err != nil {
		fmt.Printf("failed to create jwk.RSAPrivateKey from RSA private key: %s\n", err)
		return
	}

	// Once you have the typed key, you can access RSA-specific methods
	// without a type assertion.
	//
	// We won't print these values, because each time they are
	// generated the contents will be different, and thus our
	// tests would fail.
	_, _ = rsakey.D()
	_, _ = rsakey.DP()
	_, _ = rsakey.DQ()
	_, _ = rsakey.E()
	_, _ = rsakey.N()
	_, _ = rsakey.P()
	_, _ = rsakey.Q()
	_, _ = rsakey.QI()
	// OUTPUT:
	//
}
