package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_SignJSON() {
	var keys []jwk.Key

	for i := 0; i < 3; i++ {
		key, err := jwk.FromRaw([]byte(fmt.Sprintf(`abracadabra-%d`, i)))
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
	// {"payload":"TG9yZW0gaXBzdW0","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"uKad3F0NclLDZBXhuq4fDpVqQwwFLGI3opL_xMNyUTA"},{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"ghg_AA3UTfVXztTr2wRKBUcNsPE_4zYQvWoaXVVT19M"},{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"NrvTYIR4rGCG7CIn_YVtGDFvqE-ft9PqNOjIJmKlVog"}]}
}
