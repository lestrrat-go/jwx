package examples_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type Container struct {
	Key jwk.Key `json:"key"`
}

// This is only one way to parse a struct field whose dynamic
// type is unknown at compile time. In this example we use
// a proxy/wrapper to trick `Container` from attempting to
// parse the `.Key` field, and intercept the value that
// would have gone into the `Container` struct into
// `Proxy` struct's `.Key` struct field
type Proxy struct {
	Container
	Key json.RawMessage `json:"key"`
}

func ExampleJWK_StructField() {
	const src = `{
    "key": {
      "kty":"EC",
      "crv":"P-256",
      "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      "use":"enc",
      "kid":"1"
	  }
  }`

	var p Proxy
	if err := json.Unmarshal([]byte(src), &p); err != nil {
		fmt.Printf("failed to unmarshal from JSON: %s\n", err)
		return
	}

	// Parse the intercepted `Proxy.Key` as a `jwk.Key`
	// and assign it to `Container.Key`
	key, err := jwk.ParseKey(p.Key)
	if err != nil {
		fmt.Printf("failed to parse key: %s\n", err)
		return
	}
	p.Container.Key = key

	json.NewEncoder(os.Stdout).Encode(p.Container)
	// OUTPUT:
	// {"key":{"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}}
}
