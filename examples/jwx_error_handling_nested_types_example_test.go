package examples_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwx_error_handling_nested_types() {
	// Error chains can contain multiple error types. You can use errors.Is()
	// to check for any error in the chain, not just the outermost one.

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

	// Check for the outermost error type
	if errors.Is(err, jwt.ParseError()) {
		fmt.Printf("Outer error type: jwt.ParseError\n")
	}

	// Check for a nested error type - validation error is wrapped
	// inside the parse error
	if errors.Is(err, jwt.ValidateError()) {
		fmt.Printf("Contains nested: jwt.ValidateError\n")
	}

	// Check for an even more specific nested error type
	if errors.Is(err, jwt.TokenExpiredError()) {
		fmt.Printf("Contains nested: jwt.TokenExpiredError\n")
	}

	// errors.Is() traverses the entire chain, so you can check for
	// any error type at any depth. This works because ParseError wraps
	// ValidateError, which wraps TokenExpiredError.

	// OUTPUT:
	// Outer error type: jwt.ParseError
	// Contains nested: jwt.ValidateError
	// Contains nested: jwt.TokenExpiredError
}
