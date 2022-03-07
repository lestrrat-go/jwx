package examples_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_ReadFile() {
	const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo`

	msg, err := jws.Parse([]byte(src))
	if err != nil {
		fmt.Printf("failed to parse JWS message: %s\n", err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(msg)

	// OUTPUT:
	// {"payload":"TG9yZW0gaXBzdW0","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo"}
}
