package examples

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

const sampleSignedJWT = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`

func ExampleJWT_Parse() {

	// Note: this JWT has NOT been verified because we have not
	// passed jwt.WithKey() et al.
	tok, err := jwt.Parse([]byte(sampleSignedJWT))
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	_ = tok
	// OUTPUT:
}
