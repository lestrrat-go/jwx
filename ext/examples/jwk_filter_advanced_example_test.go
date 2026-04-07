package examples_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func Example_jwk_filter_advanced_use_cases() {
	// Create multiple keys with different security classifications

	// 1. High-security production key
	prodKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate production key: %s\n", err)
		return
	}
	prodJWK, err := jwk.Import[jwk.Key](prodKey)
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
	prodJWK.Set("compliance", map[string]any{
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
	devJWK, err := jwk.Import[jwk.Key](devKey)
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
	devJWK.Set("compliance", map[string]any{
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
	stagingJWK, err := jwk.Import[jwk.Key](stagingKey)
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
	stagingJWK.Set("compliance", map[string]any{
		"pci-dss": "level-3",
		"sox":     true,
		"gdpr":    true,
		"hipaa":   false,
	})
	stagingJWK.Set("auditRequired", true)
	stagingJWK.Set("backupLocation", "cloud-backup-encrypted")
	stagingJWK.Set("lastAudit", "2024-02-28T14:30:00Z")

	// Advanced Use Case 1: Security classification filter
	// Create different filters based on security levels
	publicFieldsFilter := jwk.NewFieldNameFilter(
		"securityLevel", "environment", "classification", "owner",
		"contactEmail", "purpose", "auditRequired",
	)

	confidentialFieldsFilter := jwk.NewFieldNameFilter(
		"dataTypes", "compliance", "backupLocation", "lastAudit",
	)

	// Apply public fields filter to production key
	publicProdKey, err := publicFieldsFilter.Filter(prodJWK)
	if err != nil {
		fmt.Printf("failed to create public key: %s\n", err)
		return
	}

	// Apply confidential fields filter to production key
	confidentialProdKey, err := confidentialFieldsFilter.Filter(prodJWK)
	if err != nil {
		fmt.Printf("failed to create confidential key: %s\n", err)
		return
	}

	// Advanced Use Case 2: Compliance-specific filtering
	complianceFilter := jwk.NewFieldNameFilter(
		jwk.KeyIDKey, "environment", "purpose", "compliance",
		"auditRequired", "lastAudit", "dataTypes",
	)

	// Apply compliance filter to production key for demonstration
	if _, err := complianceFilter.Filter(prodJWK); err != nil {
		fmt.Printf("failed to create compliance key: %s\n", err)
		return
	}

	// Apply compliance filter to dev key for demonstration
	if _, err := complianceFilter.Filter(devJWK); err != nil {
		fmt.Printf("failed to create compliance dev key: %s\n", err)
		return
	}

	// Advanced Use Case 3: Operational monitoring filter
	opsFilter := jwk.NewFieldNameFilter(
		jwk.KeyIDKey, "environment", "owner", "contactEmail",
		"backupLocation", "lastAudit", "auditRequired",
	)

	// Apply ops filter to staging key for demonstration
	if _, err := opsFilter.Filter(stagingJWK); err != nil {
		fmt.Printf("failed to create ops key: %s\n", err)
		return
	}

	// Advanced Use Case 4: Remove all custom metadata for pure cryptographic use
	stdFilter := jwk.ECDSAStandardFieldsFilter()
	cryptoDevKey, err := stdFilter.Filter(devJWK)
	if err != nil {
		fmt.Printf("failed to create crypto key: %s\n", err)
		return
	}

	// Validate that filtered keys have the correct structure

	// Check original production key has all expected fields
	if !prodJWK.Has("d") || !prodJWK.Has("x") || !prodJWK.Has("y") {
		fmt.Printf("missing cryptographic fields in production key\n")
		return
	}
	if !prodJWK.Has("environment") || !prodJWK.Has("classification") {
		fmt.Printf("missing metadata fields in production key\n")
		return
	}

	// Check public key excludes cryptographic data
	if publicProdKey.Has("d") || publicProdKey.Has("x") || publicProdKey.Has("y") {
		fmt.Printf("public key should not contain cryptographic fields\n")
		return
	}
	if !publicProdKey.Has("securityLevel") || !publicProdKey.Has("environment") {
		fmt.Printf("public key missing expected fields\n")
		return
	}

	// Check confidential key has restricted fields only
	if confidentialProdKey.Has("contactEmail") || confidentialProdKey.Has("owner") {
		fmt.Printf("confidential key should not contain public fields\n")
		return
	}
	if !confidentialProdKey.Has("dataTypes") || !confidentialProdKey.Has("compliance") {
		fmt.Printf("confidential key missing expected fields\n")
		return
	}

	// Check crypto-only key has standard fields but no metadata
	if cryptoDevKey.Has("environment") || cryptoDevKey.Has("classification") {
		fmt.Printf("crypto-only key should not contain metadata\n")
		return
	}
	if !cryptoDevKey.Has("kty") || !cryptoDevKey.Has("use") {
		fmt.Printf("crypto-only key missing standard JWK fields\n")
		return
	}

	// OUTPUT:
}
