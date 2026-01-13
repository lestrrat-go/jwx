package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwx_error_handling_formatting() {
	// Errors in jwx support two formatting modes:
	// - %s, %v: Standard format (shows operation and cause)
	// - %+v: Verbose format (may show additional debug information)
	//
	// Note: The difference between standard and verbose formats depends
	// on the specific error and how deep the error chain is. Some errors
	// may show the same output for both formats.

	// Create an expired token to generate a validation error
	tok, _ := jwt.NewBuilder().
		Expiration(time.Unix(1, 0)). // Set expiration to 1970-01-01
		Build()

	// Serialize it without signature for simplicity
	signed, _ := jwt.Sign(tok, jwt.WithInsecureNoSignature())

	// Try to parse with validation - will fail due to expiration
	_, err := jwt.Parse(signed, jwt.WithVerify(false), jwt.WithValidate(true))
	if err == nil {
		fmt.Printf("expected error\n")
		return
	}

	// Standard format shows the error chain
	fmt.Printf("Standard: %s\n", err)

	// Verbose format (using %+v) - in this case produces the same output
	fmt.Printf("Verbose: %+v\n", err)

	// OUTPUT:
	// Standard: jwt.Parse: failed to parse token: jwt.Validate: validation failed: "exp" not satisfied: token is expired
	// Verbose: jwt.Parse: failed to parse token: jwt.Validate: validation failed: "exp" not satisfied: token is expired
}
