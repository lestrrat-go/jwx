package examples

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func ExampleJWK_Comparison() {
	genKey := func() (jwk.Key, error) {
		raw, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new RSA private key: %s", err)
		}

		key, err := jwk.FromRaw(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to create RSA key: %s", err)
		}
		if _, ok := key.(jwk.RSAPrivateKey); !ok {
			return nil, fmt.Errorf("expected jwk.SymmetricKey, got %T", key)
		}

		return key, nil
	}

	k1, err := genKey()
	if err != nil {
		fmt.Printf("failed to generate key 1: %T", err)
		return
	}
	k2, err := genKey()
	if err != nil {
		fmt.Printf("failed to generate key 2: %T", err)
		return
	}

	// This comparison only compares Thumbprints of each key. It does NOT take into
	// account fields that could differ even when thumbprints match. For example,
	// it is totally possible to have a key with the same thumbprint, but different
	// Key IDs, or key usages.
	if jwk.Equal(k1, k2) {
		fmt.Printf("k1 and k2 should be different")
		return
	}

	if !jwk.Equal(k1, k1) {
		fmt.Printf("k1 and k1 should be equal")
		return
	}
}
