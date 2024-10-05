package examples

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWTPlainStruct() {
	t1, err := jwt.NewBuilder().
		Issuer("https://github.com/lestrrat-go/jwx/v3/examples").
		Subject("raw_struct").
		Claim("private", "foobar").
		Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build JWT: %s\n", err)
	}

	key := []byte("secret")
	signed, err := jwt.Sign(t1, jwt.WithKey(jwa.HS256(), key))
	if err != nil {
		fmt.Printf("failed to sign JWT: %s\n", err)
	}

	rawJWT, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
	if err != nil {
		fmt.Printf("failed to verify JWS: %s\n", err)
	}

	type MyToken struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
		Private string `json:"private"`
	}

	var t2 MyToken
	if err := json.Unmarshal(rawJWT, &t2); err != nil {
		fmt.Printf("failed to unmarshal JWT: %s\n", err)
	}

	fmt.Printf("%s\n", t2.Private)
	// OUTPUT:
	// foobar
}
