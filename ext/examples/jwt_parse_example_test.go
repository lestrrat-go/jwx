package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_parse() {
	tok, err := jwt.Parse(jwtSignedWithHS256, jwt.WithKey(jwa.HS256(), jwkSymmetricKey))
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	_ = tok
	// OUTPUT:
}
