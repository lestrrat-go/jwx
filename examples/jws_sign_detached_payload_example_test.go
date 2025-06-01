package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func Example_jws_sign_detached_payload() {
	payload := `$.02`

	key, err := jwk.Import([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	// If you plan to transmit your payload without base64-encoding (RFC 7797),
	// it's best to set `b64: false` so libraries can act accordingly (e.g. the
	// popular NodeJS `jose` library requires it set to false in order to verify
	// a plaintext payload.
	hdrs := jws.NewHeaders()
	hdrs.Set("b64", false)
	hdrs.Set("crit", []string{"b64"})
	
	serialized, err := jws.Sign(nil, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)), jws.WithDetachedPayload([]byte(payload)))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	fmt.Printf("%s\n", serialized)
	// OUTPUT:
	// eyJhbGciOiJIUzI1NiJ9..H14oXKwyvAsl0IbBLjw9tLxNIoYisuIyb_oDV4-30Vk
}
