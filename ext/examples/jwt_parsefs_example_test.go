package examples_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwt_ParseFS() {
	f, err := os.CreateTemp(``, `jwt_parsefs-*.jws`)
	if err != nil {
		fmt.Printf("failed to create temporary file: %s\n", err)
		return
	}
	defer os.Remove(f.Name())

	fmt.Fprint(f, exampleJWTSignedHMAC)
	f.Close()

	// Note: this JWT has NOT been verified because we have not passed jwt.WithKey() and used
	// jwt.WithVerify(false). You need to pass jwt.WithKey() if you want the token to be parsed and
	// verified in one go.
	tok, err := jwt.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		fmt.Printf("failed to read file %q: %s\n", f.Name(), err)
		return
	}
	_ = tok
	// OUTPUT:
}
