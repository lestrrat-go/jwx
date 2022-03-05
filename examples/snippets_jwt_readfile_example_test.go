package examples

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ReadFile() {
	f, err := ioutil.TempFile(``, `snippet_jwt_readfile-*.jws`)
	if err != nil {
		log.Printf(`failed to create temporary file: %s`, err)
		return
	}
	defer os.Remove(f.Name())

	fmt.Fprintf(f, sampleSignedJWT)
	f.Close()

	// Note: this JWT has NOT been verified because we have not
	// passed jwt.WithKey() et al.
	tok, err := jwt.ReadFile(f.Name())
	if err != nil {
		log.Printf(`failed to read file %q: %s`, f.Name(), err)
		return
	}
	_ = tok
	// OUTPUT:
}
