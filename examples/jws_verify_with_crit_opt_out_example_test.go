package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func Example_jws_verify_with_crit_opt_out() {
	// This JWS has a "crit" header listing "x-custom", but the "x-custom"
	// header is not present in the protected header. Per RFC 7515 Section
	// 4.1.11, this should be rejected.
	const src = `eyJhbGciOiJIUzI1NiIsImNyaXQiOlsieC1jdXN0b20iXX0.TG9yZW0gaXBzdW0.nqgPb01MwodtcEhQ-Hm0zWTrpa5whLjI9D-xZj-PrDo`

	key, err := jwk.Import([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create key: %s\n", err)
		return
	}

	// By default, jws.Verify validates the "crit" header and rejects
	// this message because "x-custom" is not present.
	_, err = jws.Verify([]byte(src), jws.WithKey(jwa.HS256(), key))
	if err != nil {
		fmt.Printf("strict crit (default): %s\n", err)
	}

	// WithStrictCriticalHeaders(false) skips "crit" validation,
	// restoring the pre-v3.0.14 behavior.
	payload, err := jws.Verify([]byte(src), jws.WithKey(jwa.HS256(), key), jws.WithStrictCriticalHeaders(false))
	if err != nil {
		fmt.Printf("failed to verify payload: %s\n", err)
		return
	}
	fmt.Printf("relaxed crit: %s\n", payload)
	// OUTPUT:
	// strict crit (default): jws.Verify: could not verify message using any of the signatures or keys: jws.Verify: signature #1 has invalid "crit" header: jws.Verify: "crit" header references extension "x-custom", but it is not present in the protected header
	// relaxed crit: Lorem ipsum
}
