package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func ExampleJWE_Encrypt() {
	rawprivkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to create raw private key: %s\n", err)
		return
	}
	privkey, err := jwk.Import(rawprivkey)
	if err != nil {
		fmt.Printf("failed to create private key: %s\n", err)
		return
	}

	pubkey, err := privkey.PublicKey()
	if err != nil {
		fmt.Printf("failed to create public key:%s\n", err)
		return
	}

	const payload = `Lorem ipsum`
	encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP, pubkey))
	if err != nil {
		fmt.Printf("failed to encrypt payload: %s\n", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, privkey))
	if err != nil {
		fmt.Printf("failed to decrypt payload: %s\n", err)
		return
	}
	fmt.Printf("%s\n", decrypted)
	// OUTPUT:
	// Lorem ipsum
}
