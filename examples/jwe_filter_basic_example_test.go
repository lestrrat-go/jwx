package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Example_jwe_filter_basic demonstrates basic JWE HeaderFilter functionality
// with HeaderNameFilter.Filter(), StandardHeadersFilter(), and HeaderNameFilter.Reject() methods.
func Example_jwe_filter_basic() {
	// Generate RSA key for encryption
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Failed to generate RSA private key: %s\n", err)
		return
	}

	jwkPrivKey, err := jwk.Import(privKey)
	if err != nil {
		fmt.Printf("Failed to import private key: %s\n", err)
		return
	}

	jwkPubKey, err := jwk.Import(privKey.PublicKey)
	if err != nil {
		fmt.Printf("Failed to import public key: %s\n", err)
		return
	}

	// Sample payload
	payload := []byte(`{"message": "Hello World", "user": "alice"}`)

	// Create JWE token with custom headers
	protectedHeaders := jwe.NewHeaders()
	protectedHeaders.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256())
	protectedHeaders.Set(jwe.ContentEncryptionKey, jwa.A256GCM)
	protectedHeaders.Set(jwe.ContentTypeKey, "application/json")
	protectedHeaders.Set(jwe.KeyIDKey, "example-key-1")
	protectedHeaders.Set("custom-header", "custom-value")
	protectedHeaders.Set("app-id", "my-app")
	protectedHeaders.Set("version", "1.0")

	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.RSA_OAEP_256(), jwkPubKey), jwe.WithProtectedHeaders(protectedHeaders))
	if err != nil {
		fmt.Printf("Failed to encrypt JWE: %s\n", err)
		return
	}

	// Parse the JWE to get the headers
	message, err := jwe.Parse(encrypted)
	if err != nil {
		fmt.Printf("Failed to parse JWE: %s\n", err)
		return
	}

	headers := message.ProtectedHeaders()

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

	// Verify the token can still be decrypted with filtered headers
	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP_256(), jwkPrivKey))
	if err != nil {
		fmt.Printf("Failed to decrypt JWE: %s\n", err)
		return
	}
	if string(decrypted) != string(payload) {
		fmt.Printf("Decrypted payload does not match original\n")
		return
	}

	// OUTPUT:
}

// printJWEBasicHeaders prints the values of headers for basic example demonstration
func printJWEBasicHeaders(headers jwe.Headers, expectedKeys []string) {
	for _, key := range expectedKeys {
		if headers.Has(key) {
			var value interface{}
			if err := headers.Get(key, &value); err == nil {
				fmt.Printf("  %s: %v\n", key, value)
			}
		}
	}
}
