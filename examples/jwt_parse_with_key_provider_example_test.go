package examples_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWT_ParseWithKeyProvider_UseToken() {
	// This example shows how one might use the information in the JWT to
	// load different keys.

	// Setup
	tok, err := jwt.NewBuilder().
		Issuer("me").
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	symmetricKey := []byte("Abracadabra")
	alg := jwa.HS256
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, symmetricKey))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	// This next example assumes that you want to minimize the number of
	// times you parse the JWT JSON
	{
		_, b64payload, _, err := jws.SplitCompact(signed)
		if err != nil {
			fmt.Printf("failed to split jws: %s\n", err)
			return
		}

		enc := base64.RawStdEncoding
		payload := make([]byte, enc.DecodedLen(len(b64payload)))
		_, err = enc.Decode(payload, b64payload)
		if err != nil {
			fmt.Printf("failed to decode base64 payload: %s\n", err)
			return
		}

		parsed, err := jwt.Parse(payload, jwt.WithVerify(false))
		if err != nil {
			fmt.Printf("failed to parse JWT: %s\n", err)
			return
		}

		_, err = jws.Verify(signed, jws.WithKeyProvider(jws.KeyProviderFunc(func(_ context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
			switch parsed.Issuer() {
			case "me":
				sink.Key(alg, symmetricKey)
				return nil
			default:
				return fmt.Errorf("unknown issuer %q", parsed.Issuer())
			}
		})))

		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}

		if parsed.Issuer() != tok.Issuer() {
			fmt.Printf("issuers do not match\n")
			return
		}
	}

	// OUTPUT:
	//
}

func ExampleJWT_ParseWithKeyProvider() {
	// Pretend that this is a storage somewhere (maybe a database) that maps
	// a signature algorithm to a key
	store := make(map[jwa.KeyAlgorithm]interface{})
	algorithms := []jwa.SignatureAlgorithm{
		jwa.RS256,
		jwa.RS384,
		jwa.RS512,
	}
	var signingKey *rsa.PrivateKey
	for _, alg := range algorithms {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("failed to generate private key: %s\n", err)
			return
		}
		// too lazy to write a proper algorithm. just assign every
		// time, and signingKey will end up being the last key generated
		signingKey = pk
		store[alg] = pk.PublicKey
	}

	// Create a JWT
	token := jwt.New()
	token.Set(`foo`, `bar`)

	// Use the last private key in the list to sign the payload
	serialized, err := jwt.Sign(token, jwt.WithKey(algorithms[2], signingKey))
	if err != nil {
		fmt.Printf(`failed to sign JWT: %s`, err)
		return
	}

	// This example uses jws.KeyProviderFunc, but for production use
	// you should probably use a reusable object that implements
	// jws.KeyProvider
	tok, err := jwt.Parse(serialized, jwt.WithKeyProvider(jws.KeyProviderFunc(func(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
		alg := sig.ProtectedHeaders().Algorithm()
		key, ok := store[alg]
		if !ok {
			// nothing found
			return nil
		}

		// Note: we only send one key here, but we could potentially send _ALL_
		// keys in the store and have `jws.Verify()` try each one (but it would
		// most likely be a waste if you did that)
		sink.Key(alg, key)
		return nil
	})))
	if err != nil {
		fmt.Printf(`failed to verify JWT: %s`, err)
		return
	}
	_ = tok
	// OUTPUT:
}
