package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func Example_jws_verify_detached_payload() {
	serialized := `eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..lnRw_MSpQjARa5LWqPcu8Qls9p3wYGrC6tz4-nr0rkA`
	payload := `$.02`

	key, err := jwk.Import[jwk.Key]([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	verified, err := jws.Verify([]byte(serialized), jws.WithKey(jwa.HS256(), key), jws.WithDetachedPayload([]byte(payload)))
	if err != nil {
		fmt.Printf("failed to verify payload: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// $.02
}
