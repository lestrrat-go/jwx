package examples_test

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwx_error_handling_unwrap() {
	// All errors in jwx support standard Go 1.13+ error unwrapping.
	// You can traverse the error chain using errors.Unwrap() to inspect
	// the underlying causes.

	// Parse an invalid token to generate an error with a chain
	_, err := jwt.Parse([]byte("not.a.token"))
	if err == nil {
		fmt.Printf("expected error\n")
		return
	}

	// Traverse the error chain manually
	fmt.Printf("Error chain:\n")
	current := err
	depth := 0
	for current != nil {
		fmt.Printf("  [%d] %T\n", depth, current)
		current = errors.Unwrap(current)
		depth++
	}

	// The chain shows the progression from the high-level operation
	// (jwt.Parse) down to the root cause. Each level adds context
	// about what operation failed.

	// OUTPUT:
	// Error chain:
	//   [0] errors.ParseError
	//   [1] *errchain.chainedError
	//   [2] *fmt.wrapError
	//   [3] errors.ParseError
	//   [4] *errchain.chainedError
	//   [5] *errors.errorString
}
