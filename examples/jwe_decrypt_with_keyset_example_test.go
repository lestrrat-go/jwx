package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWE_VerifyWithJWKSet() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to create private key: %s\n", err)
		return
	}
	const payload = "Lorem ipsum"
	encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP, privkey.PublicKey))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	// Create a JWK Set
	set := jwk.NewSet()
	// Add some bogus keys
	k1, _ := jwk.FromRaw([]byte("abracadavra"))
	set.Add(k1)
	k2, _ := jwk.FromRaw([]byte("opensasame"))
	set.Add(k2)
	// Add the real thing
	k3, _ := jwk.FromRaw(privkey)
	k3.Set(jwk.AlgorithmKey, jwa.RSA_OAEP)
	set.Add(k3)

	// Up to this point, you probably will replace with a simple jwk.Fetch()

	if _, err := jwe.Decrypt(encrypted, jwe.WithKeySet(set, jwe.WithRequireKid(false))); err != nil {
		fmt.Printf("Failed to decrypt using jwk.Set: %s", err)
	}

	// OUTPUT:
}
