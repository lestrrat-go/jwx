package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_VerifyWithKey() {
	const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.EjVtju0uXjSz6QevNgAqN1ESd9aNCP7-tJLifkQ0_C0`

	key, err := jwk.FromRaw([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create key: %s\n", err)
		return
	}

	buf, err := jws.Verify([]byte(src), jws.WithKey(jwa.HS256, key))
	if err != nil {
		fmt.Printf("failed to verify payload: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)
	// OUTPUT:
	// Lorem ipsum
}
