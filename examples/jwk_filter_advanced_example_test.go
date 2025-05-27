package examples_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func Example_jwk_filter_advanced_use_cases() {
	// Create multiple keys with different security classifications
	set := jwk.NewSet()

	// 1. High-security production key
	prodKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate production key: %s\n", err)
		return
	}
	prodJWK, err := jwk.Import(prodKey)
	if err != nil {
		fmt.Printf("failed to import production key: %s\n", err)
		return
	}

	prodJWK.Set(jwk.KeyIDKey, "prod-ecdsa-384-2024")
	prodJWK.Set(jwk.AlgorithmKey, "ES384")
	prodJWK.Set(jwk.KeyUsageKey, "sig")
	prodJWK.Set("securityLevel", "high")
	prodJWK.Set("environment", "production")
	prodJWK.Set("classification", "confidential")
	prodJWK.Set("owner", "security-team")
	prodJWK.Set("contactEmail", "security@company.com")
	prodJWK.Set("purpose", "payment-processing")
	prodJWK.Set("dataTypes", []string{"pii", "financial", "authentication"})
	prodJWK.Set("compliance", map[string]interface{}{
		"pci-dss": "level-1",
		"sox":     true,
		"gdpr":    true,
		"hipaa":   false,
	})
	prodJWK.Set("auditRequired", true)
	prodJWK.Set("backupLocation", "hsm-cluster-primary")
	prodJWK.Set("lastAudit", "2024-03-15T09:00:00Z")

	// 2. Development key
	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate dev key: %s\n", err)
		return
	}
	devJWK, err := jwk.Import(devKey)
	if err != nil {
		fmt.Printf("failed to import dev key: %s\n", err)
		return
	}

	devJWK.Set(jwk.KeyIDKey, "dev-ecdsa-256-2024")
	devJWK.Set(jwk.AlgorithmKey, "ES256")
	devJWK.Set(jwk.KeyUsageKey, "sig")
	devJWK.Set("securityLevel", "low")
	devJWK.Set("environment", "development")
	devJWK.Set("classification", "public")
	devJWK.Set("owner", "dev-team")
	devJWK.Set("contactEmail", "dev@company.com")
	devJWK.Set("purpose", "testing")
	devJWK.Set("dataTypes", []string{"test-data", "mock-data"})
	devJWK.Set("compliance", map[string]interface{}{
		"pci-dss": "not-applicable",
		"sox":     false,
		"gdpr":    false,
		"hipaa":   false,
	})
	devJWK.Set("auditRequired", false)
	devJWK.Set("backupLocation", "local-storage")
	devJWK.Set("lastAudit", "never")

	// 3. Staging key
	stagingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate staging key: %s\n", err)
		return
	}
	stagingJWK, err := jwk.Import(stagingKey)
	if err != nil {
		fmt.Printf("failed to import staging key: %s\n", err)
		return
	}

	stagingJWK.Set(jwk.KeyIDKey, "staging-ecdsa-256-2024")
	stagingJWK.Set(jwk.AlgorithmKey, "ES256")
	stagingJWK.Set(jwk.KeyUsageKey, "sig")
	stagingJWK.Set("securityLevel", "medium")
	stagingJWK.Set("environment", "staging")
	stagingJWK.Set("classification", "internal")
	stagingJWK.Set("owner", "qa-team")
	stagingJWK.Set("contactEmail", "qa@company.com")
	stagingJWK.Set("purpose", "integration-testing")
	stagingJWK.Set("dataTypes", []string{"sanitized-production-data"})
	stagingJWK.Set("compliance", map[string]interface{}{
		"pci-dss": "level-3",
		"sox":     true,
		"gdpr":    true,
		"hipaa":   false,
	})
	stagingJWK.Set("auditRequired", true)
	stagingJWK.Set("backupLocation", "cloud-backup-encrypted")
	stagingJWK.Set("lastAudit", "2024-02-28T14:30:00Z")

	set.AddKey(prodJWK)
	set.AddKey(devJWK)
	set.AddKey(stagingJWK)

	_, err = json.MarshalIndent(set, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal full set: %s\n", err)
		return
	}

	// Advanced Use Case 1: Security classification filter
	// Create different filters based on security levels
	publicFieldsFilter := jwk.NewFieldNameFilter(
		"securityLevel", "environment", "classification", "owner",
		"contactEmail", "purpose", "auditRequired",
	)

	confidentialFieldsFilter := jwk.NewFieldNameFilter(
		"dataTypes", "compliance", "backupLocation", "lastAudit",
	)

	publicSet := jwk.NewSet()
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		publicKey, err := publicFieldsFilter.Filter(key)
		if err != nil {
			fmt.Printf("failed to create public key: %s\n", err)
			return
		}
		publicSet.AddKey(publicKey)
	}

	confidentialSet := jwk.NewSet()
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		confidentialKey, err := confidentialFieldsFilter.Filter(key)
		if err != nil {
			fmt.Printf("failed to create confidential key: %s\n", err)
			return
		}
		confidentialSet.AddKey(confidentialKey)
	}

	// Advanced Use Case 2: Compliance-specific filtering
	complianceFilter := jwk.NewFieldNameFilter(
		jwk.KeyIDKey, "environment", "purpose", "compliance",
		"auditRequired", "lastAudit", "dataTypes",
	)

	complianceSet := jwk.NewSet()
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		complianceKey, err := complianceFilter.Filter(key)
		if err != nil {
			fmt.Printf("failed to create compliance key: %s\n", err)
			return
		}
		complianceSet.AddKey(complianceKey)
	}

	// Advanced Use Case 3: Operational monitoring filter
	opsFilter := jwk.NewFieldNameFilter(
		jwk.KeyIDKey, "environment", "owner", "contactEmail",
		"backupLocation", "lastAudit", "auditRequired",
	)

	opsSet := jwk.NewSet()
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		opsKey, err := opsFilter.Filter(key)
		if err != nil {
			fmt.Printf("failed to create ops key: %s\n", err)
			return
		}
		opsSet.AddKey(opsKey)
	}

	// Advanced Use Case 4: Remove all custom metadata for pure cryptographic use
	cryptoOnlySet := jwk.NewSet()
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		stdFilter := jwk.ECDSAStandardFieldsFilter()
		cryptoKey, err := stdFilter.Filter(key)
		if err != nil {
			fmt.Printf("failed to create crypto key: %s\n", err)
			return
		}
		cryptoOnlySet.AddKey(cryptoKey)
	}

	// Validate that all expected keys are present and have the correct structure

	// Check original set has all expected fields
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		// Verify cryptographic fields exist
		if !key.Has("d") || !key.Has("x") || !key.Has("y") {
			fmt.Printf("missing cryptographic fields in key %d\n", i)
			return
		}
		// Verify metadata fields exist
		if !key.Has("environment") || !key.Has("classification") {
			fmt.Printf("missing metadata fields in key %d\n", i)
			return
		}
	}

	// Check public set excludes cryptographic data
	for i := 0; i < publicSet.Len(); i++ {
		key, ok := publicSet.Key(i)
		if !ok {
			continue
		}
		if key.Has("d") || key.Has("x") || key.Has("y") {
			fmt.Printf("public set should not contain cryptographic fields in key %d\n", i)
			return
		}
		if !key.Has("securityLevel") || !key.Has("environment") {
			fmt.Printf("public set missing expected fields in key %d\n", i)
			return
		}
	}

	// Check confidential set has restricted fields only
	for i := 0; i < confidentialSet.Len(); i++ {
		key, ok := confidentialSet.Key(i)
		if !ok {
			continue
		}
		if key.Has("contactEmail") || key.Has("owner") {
			fmt.Printf("confidential set should not contain public fields in key %d\n", i)
			return
		}
		if !key.Has("dataTypes") || !key.Has("compliance") {
			fmt.Printf("confidential set missing expected fields in key %d\n", i)
			return
		}
	}

	// Check crypto-only set has standard fields but no metadata
	for i := 0; i < cryptoOnlySet.Len(); i++ {
		key, ok := cryptoOnlySet.Key(i)
		if !ok {
			continue
		}
		if key.Has("environment") || key.Has("classification") {
			fmt.Printf("crypto-only set should not contain metadata in key %d\n", i)
			return
		}
		// Check for kty using KeyType() method instead of Has() since kty is special
		if !key.Has("kty") || !key.Has("use") {
			fmt.Printf("crypto-only set missing standard JWK fields in key %d\n", i)
			return
		}
	}

	// OUTPUT:
}
