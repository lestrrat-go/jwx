package examples_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ValidateDetectErrorType() {
	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		Expiration(time.Now().Add(-1 * time.Hour)).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	buf, err := json.Marshal(tok)
	if err != nil {
		fmt.Printf("failed to serialize token: %s\n", err)
		return
	}

	{
		// Case 1: Parsing error. We're not showing verification faiure
		// but it is about the same in the context of wanting to know
		// if it's a validation error or not
		_, err := jwt.Parse(buf[:len(buf)-1], jwt.WithValidate(true))
		if err == nil {
			fmt.Printf("token should fail parsing\n")
			return
		}

		if jwt.IsValidationError(err) {
			fmt.Printf("error should NOT be validation error\n")
			return
		}
	}

	{
		// Case 2: Parsing works, validation fails
		// NOTE: This token has NOT been verified for demonstration
		// purposes. Use `jwt.WithKey()` or the like in your production code
		_, err = jwt.Parse(buf, jwt.WithValidate(true))
		if err == nil {
			fmt.Printf("token should fail parsing\n")
			return
		}

		if !jwt.IsValidationError(err) {
			fmt.Printf("error should be validation error\n")
			return
		}

		if !errors.Is(err, jwt.ErrTokenExpired()) {
			fmt.Printf("error should be of token expired type\n")
			return
		}
		fmt.Printf("%s\n", err)
	}
	// OUTPUT:
	// "exp" not satisfied
}
