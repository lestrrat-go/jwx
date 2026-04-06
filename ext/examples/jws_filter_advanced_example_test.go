package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func Example_jws_header_filter_advanced() {
	// Create keys for multi-signature JWS
	key1, err := jwk.Import([]byte(`secret-key-1`))
	if err != nil {
		fmt.Printf("failed to create key1: %s\n", err)
		return
	}

	key2, err := jwk.Import([]byte(`secret-key-2`))
	if err != nil {
		fmt.Printf("failed to create key2: %s\n", err)
		return
	}

	// Create complex headers for first signature
	headers1 := jws.NewHeaders()
	headers1.Set(jws.KeyIDKey, "primary-key")
	headers1.Set("service", "auth-service")
	headers1.Set("version", "2.1")
	headers1.Set("security-level", "high")
	headers1.Set("internal-use", "true")

	// Create headers for second signature with different custom fields
	headers2 := jws.NewHeaders()
	headers2.Set(jws.KeyIDKey, "backup-key")
	headers2.Set("service", "backup-auth")
	headers2.Set("datacenter", "us-west")
	headers2.Set("backup-priority", "1")
	headers2.Set("internal-use", "false")

	payload := []byte(`{"action": "login", "timestamp": 1609459200}`)

	// Create a multi-signature JWS message using JSON serialization
	signed, err := jws.Sign(payload, jws.WithJSON(),
		jws.WithKey(jwa.HS256(), key1, jws.WithProtectedHeaders(headers1)),
		jws.WithKey(jwa.HS256(), key2, jws.WithProtectedHeaders(headers2)))
	if err != nil {
		fmt.Printf("failed to sign message: %s\n", err)
		return
	}

	// Parse the signed message
	parsedMsg, err := jws.Parse(signed)
	if err != nil {
		fmt.Printf("failed to parse message: %s\n", err)
		return
	}

	// Advanced filtering scenarios
	for i, sig := range parsedMsg.Signatures() {
		originalHeaders := sig.ProtectedHeaders()

		// Use case 1: Filter by service-related fields
		serviceFilter := jws.NewHeaderNameFilter("service", "datacenter", "backup-priority")
		_, err := serviceFilter.Filter(originalHeaders)
		if err != nil {
			fmt.Printf("failed to filter service headers: %s\n", err)
			continue
		}

		// Use case 2: Create public headers (remove internal fields)
		internalFilter := jws.NewHeaderNameFilter("internal-use", "security-level")
		_, err = internalFilter.Reject(originalHeaders)
		if err != nil {
			fmt.Printf("failed to create public headers: %s\n", err)
			continue
		}

		// Use case 3: Combine standard filter with custom filtering
		standardFilter := jws.StandardHeadersFilter()
		customFieldsOnly, err := standardFilter.Reject(originalHeaders)
		if err != nil {
			fmt.Printf("failed to extract custom fields: %s\n", err)
			continue
		}

		// Then filter custom fields for specific categories
		operationalFilter := jws.NewHeaderNameFilter("service", "version", "datacenter")
		_, err = operationalFilter.Filter(customFieldsOnly)
		if err != nil {
			fmt.Printf("failed to filter operational headers: %s\n", err)
			continue
		}

		if i == 0 {
			// Use case 4: Validate security requirements for first signature
			validateJWSSecurityHeaders(originalHeaders)
		}
	}

	// OUTPUT:
}

// Helper function to demonstrate validation using filtered JWS headers
func validateJWSSecurityHeaders(headers jws.Headers) {
	// Check security level
	if _, ok := headers.Field("security-level"); !ok {
		fmt.Println("✗ Security level not found")
	}

	// Check internal use flag
	if _, ok := headers.Field("internal-use"); !ok {
		fmt.Println("✗ Internal use flag missing")
	}

	// Check service identification
	if _, ok := headers.Field("service"); !ok {
		fmt.Println("✗ Service identification missing")
	}
}
