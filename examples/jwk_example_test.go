package examples_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_Usage() {
	// Use jwk.AutoRefresh if you intend to keep reuse the JWKS over and over
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

	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

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
		log.Printf("%s", jsonbuf)

		// If you know the underlying Key type (RSA, EC, Symmetric), you can
		// create an empty instance first
		//    key := jwk.NewRSAPrivateKey()
		// ..and then use json.Unmarshal
		//    json.Unmarshal(key, jsonbuf)
		//
		// but if you don't know the type first, you have an abstract type
		// jwk.Key, which can't be used as the first argument to json.Unmarshal
		//
		// In this case, use jwk.Parse()
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

func ExampleJWK_New() {
	// New returns different underlying types of jwk.Key objects
	// depending on the input value.

	// []byte -> jwk.SymmetricKey
	{
		raw := []byte("Lorem Ipsum")
		key, err := jwk.FromRaw(raw)
		if err != nil {
			fmt.Printf("failed to create symmetric key: %s\n", err)
			return
		}
		if _, ok := key.(jwk.SymmetricKey); !ok {
			fmt.Printf("expected jwk.SymmetricKey, got %T\n", key)
			return
		}
	}

	// *rsa.PrivateKey -> jwk.RSAPrivateKey
	// *rsa.PublicKey  -> jwk.RSAPublicKey
	{
		raw, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("failed to generate new RSA private key: %s\n", err)
			return
		}

		key, err := jwk.FromRaw(raw)
		if err != nil {
			fmt.Printf("failed to create RSA key: %s\n", err)
			return
		}
		if _, ok := key.(jwk.RSAPrivateKey); !ok {
			fmt.Printf("expected jwk.RSAPrivateKey, got %T\n", key)
			return
		}
		// PublicKey is omitted for brevity
	}

	// *ecdsa.PrivateKey -> jwk.ECDSAPrivateKey
	// *ecdsa.PublicKey  -> jwk.ECDSAPublicKey
	{
		raw, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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
		// PublicKey is omitted for brevity
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

func ExampleJWK_AutoRefresh() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`
	ar := jwk.NewAutoRefresh(ctx)

	// Tell *jwk.AutoRefresh that we only want to refresh this JWKS
	// when it needs to (based on Cache-Control or Expires header from
	// the HTTP response). If the calculated minimum refresh interval is less
	// than 15 minutes, don't go refreshing any earlier than 15 minutes.
	ar.Configure(googleCerts, jwk.WithMinRefreshInterval(15*time.Minute))

	// Refresh the JWKS once before getting into the main loop.
	// This allows you to check if the JWKS is available before we start
	// a long-running program
	_, err := ar.Refresh(ctx, googleCerts)
	if err != nil {
		fmt.Printf("failed to refresh google JWKS: %s\n", err)
		return
	}

	// Pretend that this is your program's main loop
MAIN:
	for {
		select {
		case <-ctx.Done():
			break MAIN
		default:
		}
		keyset, err := ar.Fetch(ctx, googleCerts)
		if err != nil {
			fmt.Printf("failed to fetch google JWKS: %s\n", err)
			return
		}
		_ = keyset

		// Do interesting stuff with the keyset... but here, we just
		// sleep for a bit
		time.Sleep(time.Second)

		// Because we're a dummy program, we just cancel the loop now.
		// If this were a real program, you prosumably loop forever
		cancel()
	}
	// OUTPUT:
}
