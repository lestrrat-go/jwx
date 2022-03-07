package examples_test

import (
	"fmt"
	"log"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_VerifyWithKey() {
	const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo`

	key, err := jwk.New([]byte(`abracadavra`))
	if err != nil {
		log.Printf("failed to create key: %s", err)
		return
	}

	buf, err := jws.Verify([]byte(src), jws.WithKey(jwa.HS256, key))
	if err != nil {
		log.Printf("failed to sign payload: %s", err)
		return
	}
	fmt.Printf("%s\n", buf)
	// OUTPUT:
	// Lorem ipsum
}
