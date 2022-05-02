package examples_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_ReadFile() {
	const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo`
	f, err := os.CreateTemp(``, `jws_readfile-*.jws`)
	if err != nil {
		fmt.Printf("failed to create temporary file: %s\n", err)
		return
	}
	defer os.Remove(f.Name())

	fmt.Fprintf(f, src)
	f.Close()

	msg, err := jws.ReadFile(f.Name())
	if err != nil {
		fmt.Printf("failed to parse JWS message: %s\n", err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(msg)

	// OUTPUT:
	// {"payload":"TG9yZW0gaXBzdW0","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo"}
}
