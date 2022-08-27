package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_SignWithHeaders() {
	key, err := jwk.FromRaw([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create key: %s\n", err)
		return
	}

	hdrs := jws.NewHeaders()
	hdrs.Set(`x-example`, true)
	buf, err := jws.Sign([]byte("Lorem ipsum"), jws.WithKey(jwa.HS256, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)
	// OUTPUT:
	// eyJhbGciOiJIUzI1NiIsIngtZXhhbXBsZSI6dHJ1ZX0.TG9yZW0gaXBzdW0.G1_mZLeYsCNCpglWcdofgoU9HExBGEMW08qzvouAzBo
}
