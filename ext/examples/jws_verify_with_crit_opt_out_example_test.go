package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func Example_jws_verify_with_crit_opt_out() {
	// This JWS has crit: ["x-custom"] with the "x-custom" header present
	// in the protected header. This is valid per RFC 7515 Section 4.1.11.
	const validCrit = `eyJhbGciOiJIUzI1NiIsImNyaXQiOlsieC1jdXN0b20iXSwieC1jdXN0b20iOiJ2YWx1ZSJ9.TG9yZW0gaXBzdW0.JGhCiLa5O8-dJqGHwzjFW_KYRAgMA85v2dlsDs2B2fc`

	// This JWS has crit: ["x-custom"] but the "x-custom" header is NOT
	// present. Per RFC 7515 Section 4.1.11, this should be rejected.
	const invalidCrit = `eyJhbGciOiJIUzI1NiIsImNyaXQiOlsieC1jdXN0b20iXX0.TG9yZW0gaXBzdW0.nqgPb01MwodtcEhQ-Hm0zWTrpa5whLjI9D-xZj-PrDo`

	key, err := jwk.Import[jwk.Key]([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to create key: %s\n", err)
		return
	}

	// By default, jws.Verify validates the "crit" header per RFC 7515.
	// A valid crit header succeeds:
	payload, err := jws.Verify([]byte(validCrit), jws.WithKey(jwa.HS256(), key))
	if err != nil {
		fmt.Printf("failed to verify: %s\n", err)
		return
	}
	fmt.Printf("strict, valid crit: %s\n", payload)

	// An invalid crit header is rejected:
	_, err = jws.Verify([]byte(invalidCrit), jws.WithKey(jwa.HS256(), key))
	fmt.Printf("strict, invalid crit: verification error = %t\n", err != nil)

	// WithStrictCriticalHeaders(false) skips "crit" validation,
	// restoring the pre-v3.0.14 behavior.
	payload, err = jws.Verify([]byte(invalidCrit), jws.WithKey(jwa.HS256(), key), jws.WithStrictCriticalHeaders(false))
	if err != nil {
		fmt.Printf("failed to verify: %s\n", err)
		return
	}
	fmt.Printf("relaxed, invalid crit: %s\n", payload)
	// OUTPUT:
	// strict, valid crit: Lorem ipsum
	// strict, invalid crit: verification error = true
	// relaxed, invalid crit: Lorem ipsum
}
