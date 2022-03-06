package examples_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

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
