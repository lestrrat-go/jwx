package examples_test

import (
	"context"
	"fmt"
	"log"

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_Usage() {
	// Use jwk.Cache if you intend to keep reuse the JWKS over and over
	set, err := jwk.Fetch(context.Background(), "https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		log.Printf("failed to parse JWK: %s", err)
		return
	}

	// Key sets can be serialized back to JSON
	{
		jsonbuf, err := json.Marshal(set)
		if err != nil {
			log.Printf("failed to marshal key set into JSON: %s", err)
			return
		}
		log.Printf("%s", jsonbuf)
	}

	for it := set.Keys(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		if err := jwk.Raw(key, &rawkey); err != nil {
			log.Printf("failed to create public key: %s", err)
			return
		}
		// Use rawkey for jws.Verify() or whatever.
		_ = rawkey

		// You can create jwk.Key from a raw key, too
		fromRawKey, err := jwk.FromRaw(rawkey)
		if err != nil {
			log.Printf("failed to acquire raw key from jwk.Key: %s", err)
			return
		}

		// Keys can be serialized back to JSON
		jsonbuf, err := json.Marshal(key)
		if err != nil {
			log.Printf("failed to marshal key into JSON: %s", err)
			return
		}

		fromJSONKey, err := jwk.Parse(jsonbuf)
		if err != nil {
			log.Printf("failed to parse json: %s", err)
			return
		}
		_ = fromJSONKey
		_ = fromRawKey
	}
	// OUTPUT:
}

//nolint:govet
func ExampleJWK_MarshalJSON() {
	// JWKs that inherently involve randomness such as RSA and EC keys are
	// not used in this example, because they may produce different results
	// depending on the environment.
	//
	// (In fact, even if you use a static source of randomness, tests may fail
	// because of internal changes in the Go runtime).

	raw := []byte("01234567890123456789012345678901234567890123456789ABCDEF")

	// This would create a symmetric key
	key, err := jwk.FromRaw(raw)
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}
	if _, ok := key.(jwk.SymmetricKey); !ok {
		fmt.Printf("expected jwk.SymmetricKey, got %T\n", key)
		return
	}

	key.Set(jwk.KeyIDKey, "mykey")

	buf, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal key into JSON: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	// OUTPUT:
	// {
	//   "k": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODlBQkNERUY",
	//   "kid": "mykey",
	//   "kty": "oct"
	// }
}
