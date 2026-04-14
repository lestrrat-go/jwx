package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

func Example_jwe_encrypt_pbes2_count() {
	password := []byte(`supersecret`)
	payload := []byte(`Lorem ipsum`)

	// Raise the PBKDF2 iteration count on the encrypt side. For
	// round-tripping with jwe.Decrypt the default max (10000) must also
	// be raised; see jwe.WithMaxPBES2Count.
	encrypted, err := jwe.Encrypt(
		payload,
		jwe.WithKey(jwa.PBES2_HS256_A128KW(), password),
		jwe.WithPBES2Count(8192),
	)
	if err != nil {
		fmt.Printf("failed to encrypt payload: %s\n", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.PBES2_HS256_A128KW(), password))
	if err != nil {
		fmt.Printf("failed to decrypt payload: %s\n", err)
		return
	}
	fmt.Printf("%s\n", decrypted)
	// OUTPUT:
	// Lorem ipsum
}
