package jwt_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

//nolint:govet
func ExampleParse_JWKS() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate private key: %s\n", err)
		return
	}

	{
		// Case 1: the Token is signed with a specific key, denoted by "kid".
		//   In this case you must obtain a KeySet with proper "kids".
		//
		//   token -> { "kid": "mykey", .... values ... }
		//   key set -> [ { ... }, { ... }, { "kid": "mykey", ... } ]
		//
		//   Then jwt.Parse() will automatically find the matching key

		var payload []byte
		var keyset *jwk.Set
		{ // Preparation:
			// For demonstration purposes, we need to do some preparation
			// Create a JWK key to sign the token (and also give a KeyID)
			realKey, err := jwk.New(privKey)
			if err != nil {
				fmt.Printf("failed to create JWK: %s\n", err)
				return
			}
			realKey.Set(jwk.KeyIDKey, `mykey`)

			// Create the token
			token := jwt.New()
			token.Set(`foo`, `bar`)

			// Sign the token and generate a payload
			signed, err := jwt.Sign(token, jwa.RS256, realKey)
			if err != nil {
				fmt.Printf("failed to generate signed payload: %s\n", err)
				return
			}

			// This is what you typically get as a signed JWT from a server
			payload = signed

			// Now create a key set that users will use to verity the signed payload against
			// Normally these keys are available somewhere like https://www.googleapis.com/oauth2/v3/certs
			pubKey, err := jwk.New(privKey.PublicKey)
			if err != nil {
				fmt.Printf("failed to create JWK: %s\n", err)
				return
			}

			// Remember, the key must have the proper "kid"
			pubKey.Set(jwk.KeyIDKey, "mykey")

			// For demonstration purposes, we also create a bogus key
			bogusKey := jwk.NewSymmetricKey()

			// This key set contains two keys, the first one is the correct one
			keyset = &jwk.Set{Keys: []jwk.Key{pubKey, bogusKey}}
		}

		{ // Actual verification:
			// FINALLY. This is how you Parse and verify the payload.
			// Key IDs are automatically matched.
			// There was a lot of code above, but as a consumer, below is really all you need
			// to write in your code
			token, err := jwt.Parse(
				bytes.NewReader(payload),
				// Tell the parser that you want to use this keyset
				jwt.WithKeySet(keyset),
			)
			if err != nil {
				fmt.Printf("failed to parse payload: %s\n", err)
			}
			_ = token
		}
	}

	{
		// Case 2: For whatever reason, we don't have a "kid" specified.
		//   Normally, this is an error, because we don't know how to select a key.
		//   But if we have only one key in the KeySet, you can explicitly ask
		//   jwt.Parse to "trust" the KeySet, and use the single key in the
		//   key set. It would be an error if you have multiple keys in the KeySet.

		var payload []byte
		var keyset *jwk.Set
		{ // Preparation:
			// Unlike our previous example, we DO NOT want to sign the payload.
			// Therefore we do NOT set the "kid" value
			realKey, err := jwk.New(privKey)
			if err != nil {
				fmt.Printf("failed to create JWK: %s\n", err)
				return
			}

			// Create the token
			token := jwt.New()
			token.Set(`foo`, `bar`)

			// Sign the token and generate a payload
			signed, err := jwt.Sign(token, jwa.RS256, realKey)
			if err != nil {
				fmt.Printf("failed to generate signed payload: %s\n", err)
				return
			}

			// This is what you typically get as a signed JWT from a server
			payload = signed

			// Now create a key set that users will use to verity the signed payload against
			// Normally these keys are available somewhere like https://www.googleapis.com/oauth2/v3/certs
			pubKey, err := jwk.New(privKey.PublicKey)
			if err != nil {
				fmt.Printf("failed to create JWK: %s\n", err)
				return
			}

			// This JWKS can *only* have 1 key.
			keyset = &jwk.Set{Keys: []jwk.Key{pubKey}}
		}

		{
			token, err := jwt.Parse(
				bytes.NewReader(payload),
				// Tell the parser that you want to use this keyset
				jwt.WithKeySet(keyset),
				// Tell the parser that you can trust this KeySet, and that
				// yo uwant to use the sole key in it
				jwt.UseDefaultKey(true),
			)
			if err != nil {
				fmt.Printf("failed to parse payload: %s\n", err)
			}
			_ = token
		}
	}

	// OUTPUT:
}

func ExampleSign() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate private key: %s\n", err)
		return
	}

	var payload []byte
	{ // Create signed payload
		token := jwt.New()
		token.Set(`foo`, `bar`)
		payload, err = jwt.Sign(token, jwa.RS256, privKey)
		if err != nil {
			fmt.Printf("failed to generate signed payload: %s\n", err)
			return
		}
	}

	{ // Parse signed payload, and perform (1) verification of the signature
		// and (2) validation of the JWT token
		// Validation can be performed in a separate step using `jwt.Validate`
		token, err := jwt.Parse(bytes.NewReader(payload),
			jwt.WithValidate(true),
			jwt.WithVerify(jwa.RS256, &privKey.PublicKey),
		)
		if err != nil {
			fmt.Printf("failed to parse JWT token: %s\n", err)
			return
		}
		buf, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			fmt.Printf("failed to generate JSON: %s\n", err)
			return
		}
		fmt.Printf("%s\n", buf)
	}
	// OUTPUT:
	// {
	//   "foo": "bar"
	// }
}

func ExampleToken() {
	t := jwt.New()
	t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/jwt`)
	t.Set(jwt.AudienceKey, `Golang Users`)
	t.Set(jwt.IssuedAtKey, time.Unix(aLongLongTimeAgo, 0))
	t.Set(`privateClaimKey`, `Hello, World!`)

	buf, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return
	}

	fmt.Printf("%s\n", buf)
	fmt.Printf("aud -> '%s'\n", t.Audience())
	fmt.Printf("iat -> '%s'\n", t.IssuedAt().Format(time.RFC3339))
	if v, ok := t.Get(`privateClaimKey`); ok {
		fmt.Printf("privateClaimKey -> '%s'\n", v)
	}
	fmt.Printf("sub -> '%s'\n", t.Subject())

	// OUTPUT:
	// {
	//   "aud": [
	//     "Golang Users"
	//   ],
	//   "iat": 233431200,
	//   "sub": "https://github.com/lestrrat-go/jwx/jwt",
	//   "privateClaimKey": "Hello, World!"
	// }
	// aud -> '[Golang Users]'
	// iat -> '1977-05-25T18:00:00Z'
	// privateClaimKey -> 'Hello, World!'
	// sub -> 'https://github.com/lestrrat-go/jwx/jwt'
}
