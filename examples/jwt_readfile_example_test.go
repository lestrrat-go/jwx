package examples_test

import (
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWT_ReadFile() {
	f, err := os.CreateTemp(``, `jwt_readfile-*.jws`)
	if err != nil {
		fmt.Printf("failed to create temporary file: %s\n", err)
		return
	}
	defer os.Remove(f.Name())

	fmt.Fprintf(f, exampleJWTSignedHMAC)
	f.Close()

	// Note: this JWT has NOT been verified because we have not passed jwt.WithKey() and used
	// jwt.WithVerify(false). You need to pass jwt.WithKey() if you want the token to be parsed and
	// verified in one go.
	tok, err := jwt.ReadFile(f.Name(), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		fmt.Printf("failed to read file %q: %s\n", f.Name(), err)
		return
	}
	_ = tok
	// OUTPUT:
}
