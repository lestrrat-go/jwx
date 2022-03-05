package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_Parse() {
	// Note: this JWT has NOT been verified because we have not
	// passed jwt.WithKey() et al. You need to pass these values
	// if you want the token to be parsed and verified in one go
	tok, err := jwt.Parse([]byte(exampleJWTSignedHMAC))
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	_ = tok
	// OUTPUT:
}
