package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ParseWithKeySet() {
	var serialized []byte
	var signingKey jwk.Key
	var keyset jwk.Set

	// Preparation:
	//
	// For demonstration purposes, we need to do some preparation
	// Create a JWK key to sign the token (and also give a KeyID),
	{
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("failed to generate private key: %s\n", err)
			return
		}
		// This is the key we will use to sign
		realKey, err := jwk.New(privKey)
		if err != nil {
			fmt.Printf("failed to create JWK: %s\n", err)
			return
		}
		realKey.Set(jwk.KeyIDKey, `mykey`)

		// For demonstration purposes, we also create a bogus key
		bogusKey := jwk.NewSymmetricKey()
		bogusKey.Set(jwk.AlgorithmKey, jwa.NoSignature)
		bogusKey.Set(jwk.KeyIDKey, "otherkey")

		// This key set contains two keys, the first one is the correct one
		keyset = jwk.NewSet()
		keyset.Add(pubKey)
		keyset.Add(bogusKey)

		signingKey = realKey
	}

	// Create the token
	token := jwt.New()
	token.Set(`foo`, `bar`)

	// Sign the token and generate a JWS message
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, realKey))
	if err != nil {
		fmt.Printf("failed to generate signed serialized: %s\n", err)
		return
	}

	// This is what you typically get as a signed JWT from a server
	serialized = signed

	// Now create a key set that users will use to verity the signed serialized against
	// Normally these keys are available somewhere like https://www.googleapis.com/oauth2/v3/certs
	pubKey, err := jwk.New(privKey.PublicKey)
	if err != nil {
		fmt.Printf("failed to create JWK: %s\n", err)
		return
	}

	// Remember, the key must have the proper "kid", and "alg"
	// If your key does not have "alg", see jwt.InferAlgorithmFromKey()
	pubKey.Set(jwk.AlgorithmKey, jwa.RS256)
	pubKey.Set(jwk.KeyIDKey, "mykey")

	// Actual verification:
	// FINALLY. This is how you Parse and verify the serialized.
	// Key IDs are automatically matched.
	// There was a lot of code above, but as a consumer, below is really all you need
	// to write in your code
	token, err := jwt.Parse(
		serialized,
		// Tell the parser that you want to use this keyset
		jwt.WithKeySet(keyset),
		// Uncomment the following option if you know your key does not have an "alg"
		// field (which is apparently the case for Azure tokens)
		// jwt.InferAlgorithmFromKey(true),
	)
	if err != nil {
		fmt.Printf("failed to parse serialized: %s\n", err)
	}
	_ = token
}
