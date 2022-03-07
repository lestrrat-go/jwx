package examples_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_Parse() {
	const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo`

	f, err := ioutil.TempFile("", "example_jws_parse-*.jws")
	if err != nil {
		fmt.Printf("failed to create temporary file: %s\n", err)
	}
	defer os.Remove(f.Name())

	f.Write([]byte(src))
	f.Close()

	msg, err := jws.ReadFile(f.Name())
	if err != nil {
		fmt.Printf("failed to parse JWS message from file %q: %s\n", f.Name(), err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(msg)
	// OUTPUT:
	// {"payload":"TG9yZW0gaXBzdW0","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo"}
}
