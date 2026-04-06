package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwt_validate_issuer() {
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
	// jwt.Validate: validation failed: "iss" not satisfied: claim "iss" does not have the expected value
}
