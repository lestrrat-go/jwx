package jwxcodegen

import "github.com/lestrrat-go/codegen"

// CaseConfig holds the common configuration for case-clause generators.
type CaseConfig struct {
	// Fields is the list of fields to generate cases for.
	Fields codegen.FieldList

	// KeyName returns the constant name for a field's JSON key
	// (e.g., "AlgorithmKey", "RSANKey").
	KeyName func(codegen.Field) string

	// ReceiverName is the variable name used in case clauses
	// (e.g., "h" for headers, "t" for tokens). Defaults to "h" if empty.
	ReceiverName string

	// Skip contains field names (unexported) to skip.
	// The caller handles these fields separately.
	Skip map[string]struct{}
}

// receiverName returns the configured receiver name, defaulting to "h".
func (c CaseConfig) receiverName() string {
	if c.ReceiverName == "" {
		return "h"
	}
	return c.ReceiverName
}

// MethodConfig holds configuration for full method generators.
type MethodConfig struct {
	// ReceiverName is the receiver variable name (e.g., "h", "t", "k").
	ReceiverName string

	// StructName is the receiver struct name (e.g., "stdHeaders", "rsaPublicKey").
	StructName string

	// Fields is the list of fields.
	Fields codegen.FieldList

	// KeyName returns the constant name for a field's JSON key.
	KeyName func(codegen.Field) string

	// PrivateParamsField is the name of the private params map field
	// (e.g., "privateParams", "privateClaims").
	PrivateParamsField string

	// FieldStorageTypeIsIndirect returns true if a field's type should be
	// stored as a pointer. Callers must provide their own function because
	// genjwt and genjwk have slightly different rules (e.g., List suffix handling).
	FieldStorageTypeIsIndirect func(codegen.Field) bool
}

// MarshalConfig holds configuration for GenerateMarshalJSON.
type MarshalConfig struct {
	MethodConfig

	// AlwaysPresentEntries are keys always included (e.g., KeyTypeKey in genjwk).
	AlwaysPresentEntries []AlwaysPresentEntry
}

// AlwaysPresentEntry represents a key-value pair that is always present
// in the marshaled output (e.g., "kty" for JWK keys).
type AlwaysPresentEntry struct {
	KeyName string // e.g., "KeyTypeKey"
	Value   string // e.g., "h.KeyType()"
}

// KeysConfig holds configuration for GenerateKeysMethod.
type KeysConfig struct {
	MethodConfig

	// AlwaysPresentKeys are keys that are always in the result (e.g., KeyTypeKey in genjwk).
	AlwaysPresentKeys []string
}

// CloneConfig holds configuration for GenerateCloneFrom.
type CloneConfig struct {
	MethodConfig

	// ExtraFieldsToCopy are additional fields to clone (e.g., "raw" in jws, "options" in jwt).
	ExtraFieldsToCopy []ExtraCloneField

	// InitPrivateParams causes the empty-case branch to initialize the
	// private params map with make() instead of setting it to nil.
	// This is used by genjwt where privateClaims must always be non-nil.
	InitPrivateParams bool
}

// ExtraCloneField represents an additional field beyond the standard
// fields that needs to be copied during cloneFrom.
type ExtraCloneField struct {
	Name string

	// IsSlice indicates whether to use slices.Clone for this field.
	IsSlice bool

	// DirectCopy indicates the field should be copied directly
	// (e.g., dst.options = src.options) without nil checking.
	DirectCopy bool
}
