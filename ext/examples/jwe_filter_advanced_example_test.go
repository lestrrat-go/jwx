package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
)

// Example_jwe_filter_advanced demonstrates advanced JWE HeaderFilter functionality
// with security filtering, service integration scenarios, and header manipulation.
func Example_jwe_filter_advanced() {
	// Create JWE headers with comprehensive metadata including security and service information
	protectedHeaders := jwe.NewHeaders()
	protectedHeaders.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256())
	protectedHeaders.Set(jwe.ContentEncryptionKey, jwa.A256GCM)
	protectedHeaders.Set(jwe.ContentTypeKey, "application/json")
	protectedHeaders.Set(jwe.KeyIDKey, "service-key-001")

	// Security headers
	protectedHeaders.Set("security_level", "high")
	protectedHeaders.Set("access_control", "restricted")
	protectedHeaders.Set("encryption_version", "v2.1")

	// Service integration headers
	protectedHeaders.Set("service_name", "user-service")
	protectedHeaders.Set("api_version", "v1.2.3")
	protectedHeaders.Set("request_id", "req-789abc")
	protectedHeaders.Set("correlation_id", "corr-456def")

	// Operational headers
	protectedHeaders.Set("environment", "production")
	protectedHeaders.Set("region", "us-east-1")
	protectedHeaders.Set("trace_id", "trace-123xyz")

	// Use the headers directly for filtering examples
	headers := protectedHeaders

	// Advanced Example 1: Service Integration - Filter service-related headers
	serviceFilter := jwe.NewHeaderNameFilter("service_name", "api_version", "request_id", "correlation_id", jwe.KeyIDKey)
	serviceHeaders, err := serviceFilter.Filter(headers)
	if err != nil {
		fmt.Printf("Failed to filter service headers: %s\n", err)
		return
	}

	// Advanced Example 2: Security Headers - Filter security-related metadata
	securityFilter := jwe.NewHeaderNameFilter("security_level", "access_control", "encryption_version", jwe.AlgorithmKey, jwe.ContentEncryptionKey)
	securityHeaders, err := securityFilter.Filter(headers)
	if err != nil {
		fmt.Printf("Failed to filter security headers: %s\n", err)
		return
	}

	// Advanced Example 3: Operational Headers - Filter operational metadata
	operationalFilter := jwe.NewHeaderNameFilter("environment", "region", "trace_id")
	operationalHeaders, err := operationalFilter.Filter(headers)
	if err != nil {
		fmt.Printf("Failed to filter operational headers: %s\n", err)
		return
	}
	// Use operationalHeaders variable by checking its length
	if len(operationalHeaders.Keys()) == 0 {
		fmt.Printf("No operational headers found\n")
		return
	}

	// Advanced Example 4: Public Headers - Remove sensitive headers for public APIs
	sensitiveFilter := jwe.NewHeaderNameFilter("security_level", "access_control", "encryption_version", "trace_id")
	publicHeaders, err := sensitiveFilter.Reject(headers)
	if err != nil {
		fmt.Printf("Failed to create public headers: %s\n", err)
		return
	}
	// Use publicHeaders variable by checking its length
	if len(publicHeaders.Keys()) == 0 {
		fmt.Printf("No public headers found\n")
		return
	}

	// Advanced Example 5: Minimal Headers - Keep only essential headers for bandwidth optimization
	essentialFilter := jwe.NewHeaderNameFilter(jwe.AlgorithmKey, jwe.ContentEncryptionKey, jwe.KeyIDKey)
	minimalHeaders, err := essentialFilter.Filter(headers)
	if err != nil {
		fmt.Printf("Failed to filter minimal headers: %s\n", err)
		return
	}
	// Use minimalHeaders variable by checking its length
	if len(minimalHeaders.Keys()) == 0 {
		fmt.Printf("No minimal headers found\n")
		return
	}

	// Advanced Example 6: Custom Validation - Filter headers based on security requirements
	isValidSecurityLevel := validateJWESecurityHeaders(securityHeaders)
	if !isValidSecurityLevel {
		fmt.Printf("Security validation failed\n")
		return
	}

	isValidServiceConfig := validateJWEServiceHeaders(serviceHeaders)
	if !isValidServiceConfig {
		fmt.Printf("Service configuration validation failed\n")
		return
	}

	// Advanced Example 7: Header transformation for different environments
	prodHeaders := createJWEEnvironmentHeaders(headers, "production")
	if len(prodHeaders.Keys()) == 0 {
		fmt.Printf("Failed to create production headers\n")
		return
	}

	testHeaders := createJWEEnvironmentHeaders(headers, "testing")
	if len(testHeaders.Keys()) == 0 {
		fmt.Printf("Failed to create testing headers\n")
		return
	}

	// OUTPUT:
}

// validateJWESecurityHeaders checks if security headers meet requirements
func validateJWESecurityHeaders(headers jwe.Headers) bool {
	// Check security level
	securityLevelV, ok := headers.Field("security_level")
	if !ok {
		return false
	}
	securityLevel, ok := securityLevelV.(string)
	if !ok || securityLevel != "high" {
		return false
	}

	// Check access control
	accessControlV, ok := headers.Field("access_control")
	if !ok {
		return false
	}
	accessControl, ok := accessControlV.(string)
	if !ok || accessControl != "restricted" {
		return false
	}

	// Check encryption algorithm
	if algValue, ok := headers.Algorithm(); !ok || algValue != jwa.RSA_OAEP_256() {
		return false
	}

	return true
}

// validateJWEServiceHeaders checks if service headers are properly configured
func validateJWEServiceHeaders(headers jwe.Headers) bool {
	requiredHeaders := []string{"service_name", "api_version", "request_id", "correlation_id"}

	for _, header := range requiredHeaders {
		if !headers.Has(header) {
			return false
		}
	}

	// Validate API version format
	apiVersionV, ok := headers.Field("api_version")
	if !ok {
		return false
	}
	apiVersion, ok := apiVersionV.(string)
	if !ok || len(apiVersion) < 5 {
		return false
	}

	return true
}

// createJWEEnvironmentHeaders creates environment-specific header configurations
func createJWEEnvironmentHeaders(originalHeaders jwe.Headers, environment string) jwe.Headers {
	switch environment {
	case "production":
		// Production: Include security and service headers, exclude debug info
		prodFilter := jwe.NewHeaderNameFilter(
			jwe.AlgorithmKey, jwe.ContentEncryptionKey, jwe.ContentTypeKey, jwe.KeyIDKey,
			"security_level", "access_control", "service_name", "api_version", "environment", "region",
		)
		filtered, err := prodFilter.Filter(originalHeaders)
		if err != nil {
			fmt.Printf("Failed to create production headers: %s\n", err)
			return jwe.NewHeaders()
		}
		return filtered

	case "testing":
		// Testing: Include debug headers, exclude some security headers
		testFilter := jwe.NewHeaderNameFilter(
			jwe.AlgorithmKey, jwe.ContentEncryptionKey, jwe.ContentTypeKey, jwe.KeyIDKey,
			"service_name", "api_version", "request_id", "correlation_id", "trace_id", "environment",
		)
		filtered, err := testFilter.Filter(originalHeaders)
		if err != nil {
			fmt.Printf("Failed to create testing headers: %s\n", err)
			return jwe.NewHeaders()
		}
		return filtered

	default:
		// Default: Use standard headers only
		stdFilter := jwe.StandardHeadersFilter()
		filtered, err := stdFilter.Filter(originalHeaders)
		if err != nil {
			fmt.Printf("Failed to create default headers: %s\n", err)
			return jwe.NewHeaders()
		}
		return filtered
	}
}
