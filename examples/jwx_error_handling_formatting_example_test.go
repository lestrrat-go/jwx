package examples_test

import (
	"fmt"

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

	// Generate an error by parsing invalid input
	_, err := jwt.Parse([]byte("not.a.token"), jwt.WithVerify(false))
	if err == nil {
		fmt.Printf("expected error\n")
		return
	}

	// Standard format
	fmt.Printf("Standard: %s\n", err)

	// Verbose format (using %+v)
	fmt.Printf("Verbose: %+v\n", err)

	// OUTPUT:
	// Standard: jwt.Parse: failed to parse token: jwt.Parse: invalid jws message: jws.Parse: failed to parse compact format: failed to parse JOSE headers: invalid character '\u009e' looking for beginning of value
	// Verbose: jwt.Parse: failed to parse token: jwt.Parse: invalid jws message: jws.Parse: failed to parse compact format: failed to parse JOSE headers: invalid character '\u009e' looking for beginning of value
}
