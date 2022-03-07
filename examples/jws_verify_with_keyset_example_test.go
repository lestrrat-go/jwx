package examples

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_VerifyWithJWKSet() {
	// Setup payload first...
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to create private key: %s", err)
		return
	}
	const payload = "Lorem ipsum"
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256, privkey))
	if err != nil {
		log.Printf("failed to sign payload: %s", err)
		return
	}

	// Create a JWK Set
	set := jwk.NewSet()
	// Add some bogus keys
	k1, _ := jwk.New([]byte("abracadavra"))
	set.Add(k1)
	k2, _ := jwk.New([]byte("opensasame"))
	set.Add(k2)
	// Add the real thing
	pubkey, _ := jwk.PublicRawKeyOf(privkey)
	k3, _ := jwk.New(pubkey)
	k3.Set(jwk.AlgorithmKey, jwa.RS256)
	set.Add(k3)

	// Up to this point, you probably will replace with a simple jwk.Fetch()

	// Now verify using the set.
	if _, err := jws.Verify(signed, jws.WithKeySet(set)); err != nil {
		fmt.Printf("Failed to verify using jwk.Set!: %s", err)
	}

	// OUTPUT:
}
