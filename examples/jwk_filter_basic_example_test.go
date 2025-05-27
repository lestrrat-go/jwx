package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func Example_jwk_filter_basic_fields() {
	// Create an RSA key and import it as a JWK with custom fields
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate RSA key: %s\n", err)
		return
	}

	key, err := jwk.Import(rsaPrivateKey)
	if err != nil {
		fmt.Printf("failed to import RSA key: %s\n", err)
		return
	}

	// Add standard fields
	key.Set(jwk.KeyIDKey, "my-rsa-key-001")
	key.Set(jwk.KeyUsageKey, "sig")
	key.Set(jwk.AlgorithmKey, "RS256")

	// Add custom fields
	key.Set("keyOwner", "alice@example.com")
	key.Set("environment", "production")
	key.Set("department", "security")
	key.Set("rotationPolicy", "quarterly")

	// Create a custom field name filter
	customFilter := jwk.NewFieldNameFilter("keyOwner", "environment", "department", "rotationPolicy")

	// Filter to get only custom fields
	customOnlyKey, err := customFilter.Filter(key)
	if err != nil {
		fmt.Printf("failed to filter custom fields: %s\n", err)
		return
	}

	// Use RSAStandardFieldsFilter to get only standard RSA JWK fields
	standardFilter := jwk.RSAStandardFieldsFilter()
	standardOnlyKey, err := standardFilter.Filter(key)
	if err != nil {
		fmt.Printf("failed to filter standard fields: %s\n", err)
		return
	}

	// Create a copy for display purposes, replacing long values with "..."
	displayKey, err := standardOnlyKey.Clone()
	if err != nil {
		fmt.Printf("failed to clone standard key: %s\n", err)
		return
	}

	// Validate that the filtering worked correctly

	// Check custom-only key has expected custom fields and no sensitive data
	if !customOnlyKey.Has("keyOwner") || !customOnlyKey.Has("environment") {
		fmt.Printf("custom key missing expected fields\n")
		return
	}
	if customOnlyKey.Has("d") || customOnlyKey.Has("n") {
		fmt.Printf("custom key should not contain cryptographic fields\n")
		return
	}

	// Check that display key has expected standard fields
	if !displayKey.Has("alg") || !displayKey.Has("kty") || !displayKey.Has("use") {
		fmt.Printf("display key missing standard JWK fields\n")
		return
	}

	// Output:
}
