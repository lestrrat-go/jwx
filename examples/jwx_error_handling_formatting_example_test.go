package examples_test

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/errchain"
)

func Example_jwx_error_handling_formatting() {
	// Errors in jwx use a chained error system that supports two formatting modes:
	// - %s, %v: Concise format (shows outermost operation and innermost cause)
	// - %+v: Verbose format (shows complete error chain with all intermediate steps)
	//
	// This example demonstrates the difference using the underlying error chain mechanism.

	// Build a multi-level error chain simulating a complex operation
	// Root cause
	rootErr := errors.New("connection refused")

	// Intermediate errors add context
	err1 := errchain.Wrap(errors.New("failed to connect to database"), rootErr)
	err2 := errchain.Wrap(errors.New("failed to initialize session"), err1)
	err3 := errchain.Wrap(errors.New("jwt.Parse: failed to validate token"), err2)

	// Concise format (%s) shows only outermost operation and innermost cause
	// This skips intermediate steps for brevity
	fmt.Printf("Concise: %s\n", err3)

	// Verbose format (%+v) shows the complete chain
	// This includes all intermediate context
	fmt.Printf("Verbose: %+v\n", err3)

	// The concise format is useful for user-facing errors where you want
	// to quickly communicate what failed and why. The verbose format is
	// valuable during debugging when you need to understand the full call path.

	// OUTPUT:
	// Concise: jwt.Parse: failed to validate token: connection refused
	// Verbose: jwt.Parse: failed to validate token: failed to initialize session: connection refused
}
