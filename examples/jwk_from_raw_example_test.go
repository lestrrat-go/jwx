package examples_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func ExampleJWK_FromRaw() {
	// First, THIS IS THE WRONG WAY TO USE jwk.FromRaw().
	//
	// Assume that the file contains a JWK in JSON format
	//
	//  buf, _ := os.ReadFile(file)
	//  key, _ := jwk.FromRaw(buf)
	//
	// This is not right, because the jwk.FromRaw() function determines
	// the type of `jwk.Key` to create based on the TYPE of the argument.
	// In this case the type of `buf` is always []byte, and therefore
	// it will always create a symmetric key.
	//
	// What you want to do is to _parse_ `buf`.
	//
	//  keyset, _ := jwk.Parse(buf)
	//  key, _    := jwk.ParseKey(buf)
	//
	// See other examples in examples/jwk_parse_key_example_test.go and
	// examples/jwk_parse_jwks_example_test.go

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
			fmt.Printf("failed to create symmetric key: %s\n", err)
			return
		}
		if _, ok := key.(jwk.RSAPrivateKey); !ok {
			fmt.Printf("expected jwk.SymmetricKey, got %T\n", key)
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
			fmt.Printf("failed to create symmetric key: %s\n", err)
			return
		}
		if _, ok := key.(jwk.ECDSAPrivateKey); !ok {
			fmt.Printf("expected jwk.SymmetricKey, got %T\n", key)
			return
		}
		// PublicKey is omitted for brevity
	}

	// OUTPUT:
}
