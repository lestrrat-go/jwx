package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

func ExampleJWE_VerifyWithKey() {
	const payload = "Lorem ipsum"
	encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP, jwkRSAPublicKey))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, jwkRSAPrivateKey))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}
	fmt.Printf("%s\n", decrypted)
	// OUTPUT:
	// Lorem ipsum
}
