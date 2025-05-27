package examples_test

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func Example_jws_header_filter_basic() {
	// Create a key for signing
	key, err := jwk.Import([]byte(`my-secret-key`))
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
	fmt.Println("Original headers:")
	printHeaders(originalHeaders)

	// Filter 1: Extract only custom fields using HeaderNameFilter
	customFilter := jws.NewHeaderNameFilter("custom-claim", "app-version", "environment")
	customOnly, err := customFilter.Filter(originalHeaders)
	if err != nil {
		fmt.Printf("failed to filter custom headers: %s\n", err)
		return
	}

	fmt.Println("\nCustom headers only:")
	printHeaders(customOnly)

	// Filter 2: Extract only standard fields using StandardHeadersFilter
	standardFilter := jws.StandardHeadersFilter()
	standardOnly, err := standardFilter.Filter(originalHeaders)
	if err != nil {
		fmt.Printf("failed to filter standard headers: %s\n", err)
		return
	}

	fmt.Println("\nStandard headers only:")
	printHeaders(standardOnly)

	// Filter 3: Remove sensitive custom fields using Reject
	sensitiveFilter := jws.NewHeaderNameFilter("custom-claim")
	publicHeaders, err := sensitiveFilter.Reject(originalHeaders)
	if err != nil {
		fmt.Printf("failed to reject sensitive headers: %s\n", err)
		return
	}

	fmt.Println("\nHeaders without sensitive data:")
	printHeaders(publicHeaders)

	// OUTPUT:
	// Original headers:
	// {
	//   "alg": "HS256",
	//   "app-version": "v1.2.3",
	//   "custom-claim": "important-data",
	//   "environment": "production",
	//   "kid": "key-2024",
	//   "typ": "JWT"
	// }
	//
	// Custom headers only:
	// {
	//   "app-version": "v1.2.3",
	//   "custom-claim": "important-data",
	//   "environment": "production"
	// }
	//
	// Standard headers only:
	// {
	//   "alg": "HS256",
	//   "kid": "key-2024",
	//   "typ": "JWT"
	// }
	//
	// Headers without sensitive data:
	// {
	//   "alg": "HS256",
	//   "app-version": "v1.2.3",
	//   "environment": "production",
	//   "kid": "key-2024",
	//   "typ": "JWT"
	// }
}

// Helper function to print headers in a readable format
func printHeaders(headers jws.Headers) {
	headerMap := make(map[string]interface{})
	for _, key := range headers.Keys() {
		var value interface{}
		if err := headers.Get(key, &value); err == nil {
			headerMap[key] = value
		}
	}

	buf, err := json.MarshalIndent(headerMap, "", "  ")
	if err != nil {
		fmt.Printf("error marshaling headers: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)
}
