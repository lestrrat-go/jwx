package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_KeySpecificMethods() {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate RSA private key: %s\n", err)
		return
	}

	key, err := jwk.FromRaw(raw)
	if err != nil {
		fmt.Printf("failed to create jwk.Key from RSA private key: %s\n", err)
		return
	}

	rsakey, ok := key.(jwk.RSAPrivateKey)
	if !ok {
		fmt.Printf("failed to convert jwk.Key into jwk.RSAPrivateKey (was %T)\n", key)
		return
	}

	// We won't print these values, because each time they are
	// generated the contents will be different, and thus our
	// tests would fail. But here you can see that once you
	// convert the type you can access the RSA-specific methods
	_ = rsakey.D()
	_ = rsakey.DP()
	_ = rsakey.DQ()
	_ = rsakey.E()
	_ = rsakey.N()
	_ = rsakey.P()
	_ = rsakey.Q()
	_ = rsakey.QI()
	// OUTPUT:
	//
}
