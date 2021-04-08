package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt/openid"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

const aLongLongTimeAgo = 233431200

//nolint:govet
func ExampleJWT_ParseWithJWKS() {
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
		var keyset jwk.Set
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
			keyset = jwk.NewSet()
			keyset.Add(pubKey)
			keyset.Add(bogusKey)
		}

		{ // Actual verification:
			// FINALLY. This is how you Parse and verify the payload.
			// Key IDs are automatically matched.
			// There was a lot of code above, but as a consumer, below is really all you need
			// to write in your code
			token, err := jwt.Parse(
				payload,
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
		var keyset jwk.Set
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
			keyset = jwk.NewSet()
			keyset.Add(pubKey)
		}

		{
			token, err := jwt.Parse(
				payload,
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

func ExampleJWT_Sign() {
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
		token, err := jwt.Parse(
			payload,
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

func ExampleJWT_Token() {
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
	//   "privateClaimKey": "Hello, World!",
	//   "sub": "https://github.com/lestrrat-go/jwx/jwt"
	// }
	// aud -> '[Golang Users]'
	// iat -> '1977-05-25T18:00:00Z'
	// privateClaimKey -> 'Hello, World!'
	// sub -> 'https://github.com/lestrrat-go/jwx/jwt'
}

func ExampleJWT_SignToken() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}

	t := jwt.New()

	{
		// Signing a token (using raw rsa.PrivateKey)
		signed, err := jwt.Sign(t, jwa.RS256, key)
		if err != nil {
			log.Printf("failed to sign token: %s", err)
			return
		}
		_ = signed
	}

	{
		// Signing a token (using JWK)
		jwkKey, err := jwk.New(key)
		if err != nil {
			log.Printf("failed to create JWK key: %s", err)
			return
		}

		signed, err := jwt.Sign(t, jwa.RS256, jwkKey)
		if err != nil {
			log.Printf("failed to sign token: %s", err)
			return
		}
		_ = signed
	}

	// OUTPUT:
}

func ExampleJWT_OpenIDToken() {
	t := openid.New()
	t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/jwt`)
	t.Set(jwt.AudienceKey, `Golang Users`)
	t.Set(jwt.IssuedAtKey, time.Unix(aLongLongTimeAgo, 0))
	t.Set(`privateClaimKey`, `Hello, World!`)

	addr := openid.NewAddress()
	addr.Set(openid.AddressPostalCodeKey, `105-0011`)
	addr.Set(openid.AddressCountryKey, `日本`)
	addr.Set(openid.AddressRegionKey, `東京都`)
	addr.Set(openid.AddressLocalityKey, `港区`)
	addr.Set(openid.AddressStreetAddressKey, `芝公園 4-2-8`)
	if err := t.Set(openid.AddressKey, addr); err != nil {
		fmt.Printf("failed to set address: %s\n", err)
		return
	}

	buf, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	t2, err := jwt.Parse(buf, jwt.WithToken(openid.New()))
	if err != nil {
		fmt.Printf("failed to parse JSON: %s\n", err)
		return
	}
	if _, ok := t2.(openid.Token); !ok {
		fmt.Printf("using jwt.WithOpenIDClaims() creates an openid.Token instance")
		return
	}
	// OUTPUT:
	// {
	//   "address": {
	//     "country": "日本",
	//     "locality": "港区",
	//     "postal_code": "105-0011",
	//     "region": "東京都",
	//     "street_address": "芝公園 4-2-8"
	//   },
	//   "aud": [
	//     "Golang Users"
	//   ],
	//   "iat": 233431200,
	//   "privateClaimKey": "Hello, World!",
	//   "sub": "https://github.com/lestrrat-go/jwx/jwt"
	// }
}
