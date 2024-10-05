package examples_test

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWX() {
	// Parse, serialize, slice and dice JWKs!
	privkey, err := jwk.ParseKey(jsonRSAPrivateKey)
	if err != nil {
		fmt.Printf("failed to parse JWK: %s\n", err)
		return
	}

	pubkey, err := jwk.PublicKeyOf(privkey)
	if err != nil {
		fmt.Printf("failed to get public key: %s\n", err)
		return
	}

	// Work with JWTs!
	{
		// Build a JWT!
		tok, err := jwt.NewBuilder().
			Issuer(`github.com/lestrrat-go/jwx`).
			IssuedAt(time.Now()).
			Build()
		if err != nil {
			fmt.Printf("failed to build token: %s\n", err)
			return
		}

		// Sign a JWT!
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privkey))
		if err != nil {
			fmt.Printf("failed to sign token: %s\n", err)
			return
		}

		// Verify a JWT!
		{
			verifiedToken, err := jwt.Parse(signed, jwt.WithKey(jwa.RS256(), pubkey))
			if err != nil {
				fmt.Printf("failed to verify JWS: %s\n", err)
				return
			}
			_ = verifiedToken
		}

		// Work with *http.Request!
		{
			req, err := http.NewRequest(http.MethodGet, `https://github.com/lestrrat-go/jwx`, nil)
			req.Header.Set(`Authorization`, fmt.Sprintf(`Bearer %s`, signed))

			verifiedToken, err := jwt.ParseRequest(req, jwt.WithKey(jwa.RS256(), pubkey))
			if err != nil {
				fmt.Printf("failed to verify token from HTTP request: %s\n", err)
				return
			}
			_ = verifiedToken
		}
	}

	// Encrypt and Decrypt arbitrary payload with JWE!
	{
		encrypted, err := jwe.Encrypt(payloadLoremIpsum, jwe.WithKey(jwa.RSA_OAEP(), jwkRSAPublicKey))
		if err != nil {
			fmt.Printf("failed to encrypt payload: %s\n", err)
			return
		}

		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP(), jwkRSAPrivateKey))
		if err != nil {
			fmt.Printf("failed to decrypt payload: %s\n", err)
			return
		}

		if !bytes.Equal(decrypted, payloadLoremIpsum) {
			fmt.Printf("verified payload did not match\n")
			return
		}
	}

	// Sign and Verify arbitrary payload with JWS!
	{
		signed, err := jws.Sign(payloadLoremIpsum, jws.WithKey(jwa.RS256(), jwkRSAPrivateKey))
		if err != nil {
			fmt.Printf("failed to sign payload: %s\n", err)
			return
		}

		verified, err := jws.Verify(signed, jws.WithKey(jwa.RS256(), jwkRSAPublicKey))
		if err != nil {
			fmt.Printf("failed to verify payload: %s\n", err)
			return
		}

		if !bytes.Equal(verified, payloadLoremIpsum) {
			fmt.Printf("verified payload did not match\n")
			return
		}
	}
	// OUTPUT:
}
