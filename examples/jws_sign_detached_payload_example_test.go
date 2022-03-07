package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_SignDetachedPayload() {
	payload := `$.02`

	key, err := jwk.New([]byte(`abracadavra`))
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	serialized, err := jws.Sign(nil, jws.WithKey(jwa.HS256, key), jws.WithDetachedPayload([]byte(payload)))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	fmt.Printf("%s\n", serialized)
	// OUTPUT:
	// eyJhbGciOiJIUzI1NiJ9..eOOVjre9XHILxvHaJpH-ZCb1TiiiTZLOY0Jhr7mwDns
}
