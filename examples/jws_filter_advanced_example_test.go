package examples_test

import (
	"encoding/json"
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

	fmt.Printf("Multi-signature JWS with %d signatures\n\n", len(parsedMsg.Signatures()))

	// Advanced filtering scenarios
	for i, sig := range parsedMsg.Signatures() {
		fmt.Printf("=== Signature %d Headers ===\n", i+1)
		originalHeaders := sig.ProtectedHeaders()

		fmt.Println("Original headers:")
		printJWSHeaders(originalHeaders)

		// Use case 1: Filter by service-related fields
		serviceFilter := jws.NewHeaderNameFilter("service", "datacenter", "backup-priority")
		serviceHeaders, err := serviceFilter.Filter(originalHeaders)
		if err != nil {
			fmt.Printf("failed to filter service headers: %s\n", err)
			continue
		}

		fmt.Println("\nService-related headers:")
		printJWSHeaders(serviceHeaders)

		// Use case 2: Create public headers (remove internal fields)
		internalFilter := jws.NewHeaderNameFilter("internal-use", "security-level")
		publicHeaders, err := internalFilter.Reject(originalHeaders)
		if err != nil {
			fmt.Printf("failed to create public headers: %s\n", err)
			continue
		}

		fmt.Println("\nPublic headers (internal fields removed):")
		printJWSHeaders(publicHeaders)

		// Use case 3: Combine standard filter with custom filtering
		standardFilter := jws.StandardHeadersFilter()
		customFieldsOnly, err := standardFilter.Reject(originalHeaders)
		if err != nil {
			fmt.Printf("failed to extract custom fields: %s\n", err)
			continue
		}

		// Then filter custom fields for specific categories
		operationalFilter := jws.NewHeaderNameFilter("service", "version", "datacenter")
		operationalHeaders, err := operationalFilter.Filter(customFieldsOnly)
		if err != nil {
			fmt.Printf("failed to filter operational headers: %s\n", err)
			continue
		}

		fmt.Println("\nOperational headers only (custom fields + specific filtering):")
		printJWSHeaders(operationalHeaders)

		if i == 0 {
			// Use case 4: Validate security requirements for first signature
			fmt.Println("\nSecurity validation for primary signature:")
			validateJWSSecurityHeaders(originalHeaders)
		}

		fmt.Println()
	}

	// OUTPUT:
	// Multi-signature JWS with 2 signatures
	//
	// === Signature 1 Headers ===
	// Original headers:
	// {
	//   "alg": "HS256",
	//   "internal-use": "true",
	//   "kid": "primary-key",
	//   "security-level": "high",
	//   "service": "auth-service",
	//   "version": "2.1"
	// }
	//
	// Service-related headers:
	// {
	//   "service": "auth-service"
	// }
	//
	// Public headers (internal fields removed):
	// {
	//   "alg": "HS256",
	//   "kid": "primary-key",
	//   "service": "auth-service",
	//   "version": "2.1"
	// }
	//
	// Operational headers only (custom fields + specific filtering):
	// {
	//   "service": "auth-service",
	//   "version": "2.1"
	// }
	//
	// Security validation for primary signature:
	// ✓ Security level: high
	// ✓ Internal use flag present
	// ✓ Service identification: auth-service
	//
	// === Signature 2 Headers ===
	// Original headers:
	// {
	//   "alg": "HS256",
	//   "backup-priority": "1",
	//   "datacenter": "us-west",
	//   "internal-use": "false",
	//   "kid": "backup-key",
	//   "service": "backup-auth"
	// }
	//
	// Service-related headers:
	// {
	//   "backup-priority": "1",
	//   "datacenter": "us-west",
	//   "service": "backup-auth"
	// }
	//
	// Public headers (internal fields removed):
	// {
	//   "alg": "HS256",
	//   "backup-priority": "1",
	//   "datacenter": "us-west",
	//   "kid": "backup-key",
	//   "service": "backup-auth"
	// }
	//
	// Operational headers only (custom fields + specific filtering):
	// {
	//   "datacenter": "us-west",
	//   "service": "backup-auth"
	// }
}

// Helper function to print JWS headers in a readable format for advanced examples
func printJWSHeaders(headers jws.Headers) {
	if len(headers.Keys()) == 0 {
		fmt.Println("{}")
		return
	}

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

// Helper function to demonstrate validation using filtered JWS headers
func validateJWSSecurityHeaders(headers jws.Headers) {
	// Check security level
	var secLevel string
	if err := headers.Get("security-level", &secLevel); err == nil {
		fmt.Printf("✓ Security level: %s\n", secLevel)
	} else {
		fmt.Println("✗ Security level not found")
	}

	// Check internal use flag
	var internalUse string
	if err := headers.Get("internal-use", &internalUse); err == nil {
		fmt.Printf("✓ Internal use flag present\n")
	} else {
		fmt.Println("✗ Internal use flag missing")
	}

	// Check service identification
	var service string
	if err := headers.Get("service", &service); err == nil {
		fmt.Printf("✓ Service identification: %s\n", service)
	} else {
		fmt.Println("✗ Service identification missing")
	}
}
