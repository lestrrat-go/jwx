package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_header_filter_basic() {
	// Create a key for signing
	key, err := jwk.Import[jwk.Key]([]byte(`my-secret-key`))
	if err != nil {
		fmt.Printf("failed to create key: %s\n", err)
		return
	}

	// Create headers with both standard and custom fields
	headers := jws.NewHeaders()
	headers.Set(jws.AlgorithmKey, jwa.HS256())
	headers.Set(jws.KeyIDKey, "key-2024")
	headers.Set(jws.TypeKey, "JWT")
	headers.Set("custom-claim", "important-data")
	headers.Set("app-version", "v1.2.3")
	headers.Set("environment", "production")

	// Sign with custom headers
	payload := []byte(`{"user": "alice", "role": "admin"}`)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	// Parse the signed message to access headers
	msg, err := jws.Parse(signed)
	if err != nil {
		fmt.Printf("failed to parse: %s\n", err)
		return
	}

	originalHeaders := msg.Signatures()[0].ProtectedHeaders()

	// Filter 1: Extract only custom fields using HeaderNameFilter
	customFilter := jws.NewHeaderNameFilter("custom-claim", "app-version", "environment")
	_, err = customFilter.Filter(originalHeaders)
	if err != nil {
		fmt.Printf("failed to filter custom headers: %s\n", err)
		return
	}

	// Filter 2: Extract only standard fields using StandardHeadersFilter
	standardFilter := jws.StandardHeadersFilter()
	_, err = standardFilter.Filter(originalHeaders)
	if err != nil {
		fmt.Printf("failed to filter standard headers: %s\n", err)
		return
	}

	// Filter 3: Remove sensitive custom fields using Reject
	sensitiveFilter := jws.NewHeaderNameFilter("custom-claim")
	_, err = sensitiveFilter.Reject(originalHeaders)
	if err != nil {
		fmt.Printf("failed to reject sensitive headers: %s\n", err)
		return
	}

	// OUTPUT:
}
