package examples_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func ExampleJWK_ReadFile() {
	const src = `{
		"keys": [
      {"kty":"EC",
       "crv":"P-256",
       "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
       "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
       "use":"enc",
       "kid":"1"},
      {"kty":"RSA",
       "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
       "e":"AQAB",
       "alg":"RS256",
       "kid":"2011-04-29"}
    ]
  }`

	f, err := os.CreateTemp(``, `jwk_readfile-*.jwk`)
	if err != nil {
		fmt.Printf("failed to create temporary file: %s\n", err)
		return
	}
	defer os.Remove(f.Name())

	fmt.Fprintf(f, src)
	f.Close()

	key, err := jwk.ReadFile(f.Name())
	if err != nil {
		fmt.Printf("failed to parse key: %s\n", err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(key)

	// OUTPUT:
	// {"keys":[{"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}]}
}
