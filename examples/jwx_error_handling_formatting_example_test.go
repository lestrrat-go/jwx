package examples_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwx_error_handling_formatting() {
	// Errors in jwx support two formatting modes:
	// - %s, %v: Concise format (shows outermost operation and innermost cause)
	// - %+v: Verbose format (shows additional intermediate context)
	//
	// This example demonstrates the difference using a real JWT validation error.

	// Create an expired token
	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		Expiration(time.Now().Add(-1 * time.Hour)). // Expired 1 hour ago
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

	// Parse with validation enabled (note: no signature verification for demo)
	_, err = jwt.Parse(buf, jwt.WithVerify(false), jwt.WithValidate(true))
	if err == nil {
		fmt.Printf("expected validation to fail\n")
		return
	}

	// Concise format (%s) shows only outermost operation and innermost cause
	// This is ideal for user-facing error messages
	fmt.Printf("Concise: %s\n", err)

	// Verbose format (%+v) shows additional intermediate context
	// This reveals that jwt.Validate was the intermediate step that failed
	fmt.Printf("Verbose: %+v\n", err)

	// OUTPUT:
	// Concise: jwt.Parse: "exp" not satisfied: token is expired
	// Verbose: jwt.Parse: jwt.Validate: validation failed: "exp" not satisfied: token is expired
}
