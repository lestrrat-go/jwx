package examples_test

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwx_error_handling_unwrap() {
	// All errors in jwx support standard Go 1.13+ error unwrapping.
	// You can traverse the error chain using errors.Unwrap() to inspect
	// each level and extract specific information.

	// Parse an invalid token to generate an error with a chain
	_, err := jwt.Parse([]byte("not.a.token"))
	if err == nil {
		fmt.Printf("expected error\n")
		return
	}

	// Check if it's a parse error
	if errors.Is(err, jwt.ParseError()) {
		fmt.Printf("Top-level error: jwt.ParseError\n")
	}

	// Traverse the error chain to inspect each level
	fmt.Printf("\nError messages at each level:\n")
	current := err
	depth := 0
	for current != nil && depth < 3 {
		// Print a truncated version of the error message
		msg := current.Error()
		if len(msg) > 60 {
			msg = msg[:60] + "..."
		}
		fmt.Printf("  [%d] %s\n", depth, msg)

		current = errors.Unwrap(current)
		depth++
	}

	// Notice that [0] and [1] show the same message. This is because the
	// outer ParseError type is a transparent wrapper that forwards its
	// Error() call to the wrapped error. Both levels return the same
	// concise error string (outermost operation + innermost cause).

	// OUTPUT:
	// Top-level error: jwt.ParseError
	//
	// Error messages at each level:
	//   [0] jwt.Parse: no keys for verification are provided (use jwt.Wi...
	//   [1] jwt.Parse: no keys for verification are provided (use jwt.Wi...
	//   [2] no keys for verification are provided (use jwt.WithVerify(fa...
}
