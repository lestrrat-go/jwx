package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_SerializeJWEJWS() {
	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate private key: %s\n", err)
		return
	}

	enckey, err := jwk.FromRaw(privkey.PublicKey)
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	signkey, err := jwk.FromRaw([]byte(`abracadavra`))
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	serialized, err := jwt.NewSerializer().
		Encrypt(jwt.WithKey(jwa.RSA_OAEP, enckey)).
		Sign(jwt.WithKey(jwa.HS256, signkey)).
		Serialize(tok)
	if err != nil {
		fmt.Printf("failed to encrypt and sign token: %s\n", err)
		return
	}
	_ = serialized
	// We don't use the result of serialization as it will always be
	// different because of randomness used in the encryption logic
	// OUTPUT:
}
