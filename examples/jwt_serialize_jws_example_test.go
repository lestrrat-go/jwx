package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWT_SerializeJWS() {
	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	rawKey := []byte(`abracadabra`)
	jwkKey, err := jwk.Import(rawKey)
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	// This example shows you two ways to passing keys to
	// jwt.Sign()
	//
	// * The first key is the "raw" key.
	// * The second one is a jwk.Key that represents the raw key.
	//
	// If this were using RSA/ECDSA keys, you would be using
	// *rsa.PrivateKey/*ecdsa.PrivateKey as the raw key.
	for _, key := range []interface{}{rawKey, jwkKey} {
		serialized, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
		if err != nil {
			fmt.Printf("failed to sign token: %s\n", err)
			return
		}

		fmt.Printf("%s\n", serialized)
	}

	// OUTPUT:
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjIzMzQzMTIwMCwiaXNzIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ.K1WVWaM6Dww9aNNFMjnyUfjaaHIs08-3Qb1b8eSEHOk
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjIzMzQzMTIwMCwiaXNzIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ.K1WVWaM6Dww9aNNFMjnyUfjaaHIs08-3Qb1b8eSEHOk
}
