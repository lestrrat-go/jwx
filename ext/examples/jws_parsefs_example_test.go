package examples_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_ParseFS() {
	const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo`
	f, err := os.CreateTemp(``, `jws_parsefs-*.jws`)
	if err != nil {
		fmt.Printf("failed to create temporary file: %s\n", err)
		return
	}
	defer os.Remove(f.Name())

	fmt.Fprint(f, src)
	f.Close()

	msg, err := jws.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()))
	if err != nil {
		fmt.Printf("failed to parse JWS message: %s\n", err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(msg)

	// OUTPUT:
	// {"payload":"TG9yZW0gaXBzdW0","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo"}
}
