package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
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
		realKey, err := jwk.FromRaw(privKey)
		if err != nil {
			fmt.Printf("failed to create JWK: %s\n", err)
			return
		}
		realKey.Set(jwk.KeyIDKey, `mykey`)
		realKey.Set(jwk.AlgorithmKey, jwa.RS256)

		// For demonstration purposes, we also create a bogus key
		bogusKey, err := jwk.FromRaw([]byte("bogus"))
		if err != nil {
			fmt.Printf("failed to create bogus JWK: %s\n", err)
			return
		}
		bogusKey.Set(jwk.AlgorithmKey, jwa.NoSignature)
		bogusKey.Set(jwk.KeyIDKey, "otherkey")

		// Now create a key set that users will use to verity the signed serialized against
		// Normally these keys are available somewhere like https://www.googleapis.com/oauth2/v3/certs
		// This key set contains two keys, the first one is the correct one

		// We can use the jwk.PublicSetOf() utility to get a JWKS
		// all of the public keys
		{
			privset := jwk.NewSet()
			privset.AddKey(realKey)
			privset.AddKey(bogusKey)
			v, err := jwk.PublicSetOf(privset)
			if err != nil {
				fmt.Printf("failed to create public JWKS: %s\n", err)
				return
			}
			keyset = v
		}

		signingKey = realKey
	}

	// Create the token
	token := jwt.New()
	token.Set(`foo`, `bar`)

	// Sign the token and generate a JWS message
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, signingKey))
	if err != nil {
		fmt.Printf("failed to generate signed serialized: %s\n", err)
		return
	}

	// This is what you typically get as a signed JWT from a server
	serialized = signed

	// Actual verification:
	// FINALLY. This is how you Parse and verify the serialized.
	// Key IDs are automatically matched.
	// There was a lot of code above, but as a consumer, below is really all you need
	// to write in your code
	tok, err := jwt.Parse(
		serialized,
		// Tell the parser that you want to use this keyset
		jwt.WithKeySet(keyset),

		// Replace the above option with the following option if you know your key
		// does not have an "alg"/ field (which is apparently the case for Azure tokens)
		// jwt.WithKeySet(keyset, jws.WithInferAlgorithmFromKey(true)),
	)
	if err != nil {
		fmt.Printf("failed to parse serialized: %s\n", err)
	}
	_ = tok
	// OUTPUT:
}
