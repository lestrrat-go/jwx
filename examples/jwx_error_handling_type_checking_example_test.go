package examples_test

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwx_error_handling_type_checking() {
	// All jwx packages use consistent error handling patterns.
	// Use errors.Is() to check error types across jwt, jws, jwe, and jwk.
	// This example demonstrates parse errors, which are common across all packages.

	// JWT Parse Error
	{
		_, err := jwt.Parse([]byte("invalid-jwt-token"))
		if err == nil {
			fmt.Printf("expected error\n")
			return
		}

		if errors.Is(err, jwt.ParseError()) {
			fmt.Printf("JWT: errors.Is() detected parse error\n")
		}
	}

	// JWS Parse Error
	{
		_, err := jws.Parse([]byte("invalid-jws"))
		if err == nil {
			fmt.Printf("expected error\n")
			return
		}

		if errors.Is(err, jws.ParseError()) {
			fmt.Printf("JWS: errors.Is() detected parse error\n")
		}
	}

	// JWE Parse Error
	{
		_, err := jwe.Parse([]byte("invalid-jwe"))
		if err == nil {
			fmt.Printf("expected error\n")
			return
		}

		if errors.Is(err, jwe.ParseError()) {
			fmt.Printf("JWE: errors.Is() detected parse error\n")
		}
	}

	// JWK Parse Error
	{
		_, err := jwk.ParseKey([]byte("invalid-jwk"))
		if err == nil {
			fmt.Printf("expected error\n")
			return
		}

		if errors.Is(err, jwk.ParseError()) {
			fmt.Printf("JWK: errors.Is() detected parse error\n")
		}
	}

	// OUTPUT:
	// JWT: errors.Is() detected parse error
	// JWS: errors.Is() detected parse error
	// JWE: errors.Is() detected parse error
	// JWK: errors.Is() detected parse error
}
