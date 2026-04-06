package examples_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwt_validate_detect_error_type() {
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
		// Case 1: Parsing error. We're not showing verification failure,
		// but it is about the same in the context of wanting to know
		// if it's a validation error or not
		_, err := jwt.Parse(buf[:len(buf)-1], jwt.WithVerify(false), jwt.WithValidate(true))
		if err == nil {
			fmt.Printf("token should fail parsing\n")
			return
		}

		if errors.Is(err, jwt.ValidationError{}) {
			fmt.Printf("error should NOT be validation error\n")
			return
		}
	}

	{
		// Case 2: Parsing works, validation fails
		// NOTE: This token has NOT been verified for demonstration
		// purposes. Use `jwt.WithKey()` or the like in your production code
		_, err = jwt.Parse(buf, jwt.WithVerify(false), jwt.WithValidate(true))
		if err == nil {
			fmt.Printf("token should fail parsing\n")
			return
		}

		if !errors.Is(err, jwt.ValidationError{}) {
			fmt.Printf("error should be validation error\n")
			return
		}

		if !errors.Is(err, jwt.TokenExpiredError{}) {
			fmt.Printf("error should be of token expired type\n")
			return
		}

		fmt.Printf("%s\n", err)
	}
	// OUTPUT:
	// jwt.Parse: failed to parse token: jwt.Validate: validation failed: "exp" not satisfied: token is expired
}
