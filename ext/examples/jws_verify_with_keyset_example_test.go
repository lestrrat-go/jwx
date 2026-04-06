package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func Example_jws_verify_with_jwk_set() {
	// Setup payload, private key, and signed payload first...
	const payload = "Lorem ipsum"
	privkey, err := jwxtest.GenerateRsaJwk()
	if err != nil {
		fmt.Printf("failed to create private key: %s\n", err)
		return
	}
	const keyID = "correct-key"
	_ = privkey.Set(jwk.KeyIDKey, keyID)

	// Create a JWK Set
	set := jwk.NewSet()
	// Add some bogus keys
	k1, _ := jwk.Import([]byte("abracadabra"))
	_ = set.AddKey(k1)
	_ = k1.Set(jwk.KeyIDKey, "key-01")

	k2, _ := jwk.Import([]byte("opensesame"))
	_ = set.AddKey(k2)
	_ = k1.Set(jwk.KeyIDKey, "key-02")

	// AddKey the real thing. Note that k3 already contains the Key ID because
	// jwk.PublicKeyOf(jwk) automatically sets the Key ID if it is present in the private key.
	k3, _ := jwk.PublicKeyOf(privkey)
	_ = set.AddKey(k3)

	// Up to this point, you probably will replace with a simple jwk.Fetch()
	// or similar to obtain the JWKS

	// Sign with a key that has a Key ID. This forces jws.Sign() to include its
	// key ID in the JWS header.
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), privkey))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	// Now let's try to verify the signed payload under various conditions

	{ // No Key ID, nor algorithm present in the key}
		k3.Remove(jwk.KeyIDKey) // Remove Key ID so that it won't work

		// This fails, because it's going to try to lookup a key to use using the Key ID,
		// but it can't be found
		if _, err := jws.Verify(signed, jws.WithKeySet(set)); err == nil {
			fmt.Printf("Able to verify using jwk.Set, when it shouldn't: %s", err)
			return
		}

		// Now let's add a WithRequireKid(false). This will STILL fail, because the key
		// matching the key ID doesn't have an algorithm value set.
		if _, err := jws.Verify(signed, jws.WithKeySet(set, jws.WithRequireKid(false))); err == nil {
			fmt.Printf("Able to verify using jwk.Set, when it shouldn't: %s", err)
			return
		}

		// This works, because we're telling it to infer the algorithm by the
		// key type.
		if _, err := jws.Verify(signed, jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true), jws.WithRequireKid(false))); err != nil {
			fmt.Printf("Failed to verify using jwk.Set: %s", err)
			return
		}
	}

	{ // Key ID present, but no algorithm
		k3.Set(jwk.KeyIDKey, keyID) // Add Key ID back

		// This does not work because the while the library can find
		// a key matching the key ID, it doesn't know what algorithm to use
		if _, err := jws.Verify(signed, jws.WithKeySet(set)); err == nil {
			fmt.Printf("Able to verify using jwk.Set, when it shouldn't: %s", err)
			return
		}

		// This works, because the library can find a key matching the key ID,
		// and it can infer the algorithm from the key type
		if _, err := jws.Verify(signed, jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true))); err != nil {
			fmt.Printf("Failed to verify using jwk.Set: %s", err)
			return
		}
	}

	{ // both Key ID and algorithm present
		// And finally, the "cleanest" way.
		k3.Set(jwk.AlgorithmKey, jwa.RS256()) // Set algorithm

		if _, err := jws.Verify(signed, jws.WithKeySet(set)); err != nil {
			fmt.Printf("Failed to verify using jwk.Set: %s", err)
			return
		}
	}

	// If you just can't do this (e.g. because your token doesn't have a Key ID),
	// then you're better off using the single-key option jws.WithKey() (or the jwt.WithKey() option)

	// OUTPUT:
}
