package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func ExampleJWS_SignJSON() {
	var keys []jwk.Key

	for i := 0; i < 3; i++ {
		key, err := jwk.Import([]byte(fmt.Sprintf(`abracadabra-%d`, i)))
		if err != nil {
			fmt.Printf("failed to create key: %s\n", err)
			return
		}
		keys = append(keys, key)
	}

	options := []jws.SignOption{jws.WithJSON()}
	for _, key := range keys {
		options = append(options, jws.WithKey(jwa.HS256, key))
	}

	buf, err := jws.Sign([]byte("Lorem ipsum"), options...)
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)
	// OUTPUT:
	// {"payload":"TG9yZW0gaXBzdW0","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"bCQtU2y4PEnG78dUN-tXea8YEwhBAzLX7ZEYlRVtX_g"},{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"0ovW79M_bbaRDBrBLaNKN7rgJeXaSRAnu5rhAuRXBR4"},{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"ZkUzwlK5E6LFKsYEIyUvskOKLMDxE0MvvkvNrwINNWE"}]}
}
