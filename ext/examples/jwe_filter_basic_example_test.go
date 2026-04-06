package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

// Example_jwe_filter_basic demonstrates basic JWE HeaderFilter functionality
// with HeaderNameFilter.Filter(), StandardHeadersFilter(), and HeaderNameFilter.Reject() methods.
func Example_jwe_filter_basic() {
	// Create JWE headers with custom headers for filtering demonstration
	protectedHeaders := jwe.NewHeaders()
	protectedHeaders.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256())
	protectedHeaders.Set(jwe.ContentEncryptionKey, jwa.A256GCM)
	protectedHeaders.Set(jwe.ContentTypeKey, "application/json")
	protectedHeaders.Set(jwe.KeyIDKey, "example-key-1")
	protectedHeaders.Set("custom-header", "custom-value")
	protectedHeaders.Set("app-id", "my-app")
	protectedHeaders.Set("version", "1.0")

	// Use the headers directly for filtering examples
	headers := protectedHeaders

	// Example 1: HeaderNameFilter.Filter() - Include only specific headers
	customFilter := jwe.NewHeaderNameFilter("custom-header", "app-id", jwe.KeyIDKey)

	filteredHeaders, err := customFilter.Filter(headers)
	if err != nil {
		fmt.Printf("HeaderNameFilter.Filter failed: %s\n", err)
		return
	}
	// Use filteredHeaders variable by checking its length
	if len(filteredHeaders.Keys()) == 0 {
		fmt.Printf("No filtered headers found\n")
		return
	}

	// Example 2: StandardHeadersFilter() - Include only standard JWE headers
	stdFilter := jwe.StandardHeadersFilter()

	standardHeaders, err := stdFilter.Filter(headers)
	if err != nil {
		fmt.Printf("StandardHeadersFilter.Filter failed: %s\n", err)
		return
	}
	// Use standardHeaders variable by checking its length
	if len(standardHeaders.Keys()) == 0 {
		fmt.Printf("No standard headers found\n")
		return
	}

	// Example 3: HeaderNameFilter.Reject() - Exclude specific headers
	rejectFilter := jwe.NewHeaderNameFilter("version", "custom-header")

	rejectedHeaders, err := rejectFilter.Reject(headers)
	if err != nil {
		fmt.Printf("HeaderNameFilter.Reject failed: %s\n", err)
		return
	}
	// Use rejectedHeaders variable by checking its length
	if len(rejectedHeaders.Keys()) == 0 {
		fmt.Printf("No rejected headers found\n")
		return
	}

	// Example 4: StandardHeadersFilter().Reject() - Exclude standard headers, keep custom
	customOnlyHeaders, err := stdFilter.Reject(headers)
	if err != nil {
		fmt.Printf("StandardHeadersFilter.Reject failed: %s\n", err)
		return
	}
	// Use customOnlyHeaders variable by checking its length
	if len(customOnlyHeaders.Keys()) == 0 {
		fmt.Printf("No custom only headers found\n")
		return
	}

	// OUTPUT:
}
