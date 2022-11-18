package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_VerifyDetachedPayload() {
	serialized := `eyJhbGciOiJIUzI1NiJ9..H14oXKwyvAsl0IbBLjw9tLxNIoYisuIyb_oDV4-30Vk`
	payload := `$.02`

	key, err := jwk.FromRaw([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	verified, err := jws.Verify([]byte(serialized), jws.WithKey(jwa.HS256, key), jws.WithDetachedPayload([]byte(payload)))
	if err != nil {
		fmt.Printf("failed to verify payload: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// $.02
}
