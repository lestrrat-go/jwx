package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWT_Parse() {
	tok, err := jwt.Parse(jwtSignedWithHS256, jwt.WithKey(jwa.HS256(), jwkSymmetricKey))
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	_ = tok
	// OUTPUT:
}
