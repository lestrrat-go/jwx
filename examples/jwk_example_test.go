package examples_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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

	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			log.Printf("failed to retrieve key %d", i)
			return
		}

		var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
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
	// to get the same values every time, we need to create a static source
	// of "randomness"
	rdr := bytes.NewReader([]byte("01234567890123456789012345678901234567890123456789ABCDEF"))
	raw, err := ecdsa.GenerateKey(elliptic.P384(), rdr)
	if err != nil {
		fmt.Printf("failed to generate new ECDSA private key: %s\n", err)
		return
	}

	key, err := jwk.FromRaw(raw)
	if err != nil {
		fmt.Printf("failed to create ECDSA key: %s\n", err)
		return
	}
	if _, ok := key.(jwk.ECDSAPrivateKey); !ok {
		fmt.Printf("expected jwk.ECDSAPrivateKey, got %T\n", key)
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
	//   "crv": "P-384",
	//   "d": "ODkwMTIzNDU2Nzg5MDEyMz7deMbyLt8g4cjcxozuIoygLLlAeoQ1AfM9TSvxkFHJ",
	//   "kid": "mykey",
	//   "kty": "EC",
	//   "x": "gvvRMqm1w5aHn7sVNA2QUJeOVcedUnmiug6VhU834gzS9k87crVwu9dz7uLOdoQl",
	//   "y": "7fVF7b6J_6_g6Wu9RuJw8geWxEi5ja9Gp2TSdELm5u2E-M7IF-bsxqcdOj3n1n7N"
	// }
}
