package examples_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_Validate() {
	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		Expiration(time.Now().Add(-1 * time.Hour)).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	{
		// Case 1: Using jwt.Validate()
		err = jwt.Validate(tok)
		if err == nil {
			fmt.Printf("token should fail validation\n")
			return
		}
		fmt.Printf("%s\n", err)
	}

	{
		// Case 2: USing jwt.Parse()
		buf, err := json.Marshal(tok)
		if err != nil {
			fmt.Printf("failed to serialize token: %s\n", err)
			return
		}

		_, err = jwt.Parse(buf, jwt.WithValidate(true))
		if err == nil {
			fmt.Printf("token should fail validation\n")
			return
		}
		fmt.Printf("%s\n", err)
	}
	// OUTPUT:
	// "exp" not satisfied
	// "exp" not satisfied
}
