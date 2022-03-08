package examples

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_ParseKey() {
	const src = `{
		"kty":"EC",
    "crv":"P-256",
    "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    "use":"enc",
    "kid":"1"
  }`

	key, err := jwk.ParseKey([]byte(src))
	if err != nil {
		fmt.Printf("failed parse key: %s\n", err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(key)
	// OUTPUT:
	// {"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
}
