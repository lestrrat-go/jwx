package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWT_ValidateIssuer() {
	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	err = jwt.Validate(tok, jwt.WithIssuer(`nobody`))
	if err == nil {
		fmt.Printf("token should fail validation\n")
		return
	}
	fmt.Printf("%s\n", err)
	// OUTPUT:
	// "iss" not satisfied: values do not match
}
