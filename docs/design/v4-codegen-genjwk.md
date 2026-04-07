# Refactor genjwk (JWK Key Generator)

## Motivation

`genjwk/main.go` is the largest generator at 884 lines. Its core function `generateObject` is 530 lines — a single function that generates interface definitions, struct types, constructors, getters, Has, Get, Set, Remove, Clone, DecodeCtx, UnmarshalJSON, makePairs, MarshalJSON, and Keys methods all in one monolithic block. This makes the code hard to navigate, modify, and review.

The generator also has unique complexity: it handles multiple key types (RSA, ECDSA, OKP, Symmetric), each with public/private variants, standard fields shared across all types, and key-type-specific fields with prefixed constant names.

## Current Structure

```
_main()                                          lines 53-92
  → generateGenericHeaders(stdFields, keyTypes)  lines 784-884  (100 lines)
  → generateKeyType(kt, stdFields)               lines 118-197  (80 lines)
      → generateObject(o, kt, obj)               lines 255-781  (527 lines)
      → generateStandardFieldsFilterWithFields()  lines 200-253  (54 lines)
```

## Proposed Changes

### Break down `generateObject` into focused functions

Each function takes `*codegen.Output`, the `KeyType`, and the `*codegen.Object`, plus any additional parameters it needs.

```go
// generateKeyInterface emits the per-key-type interface (e.g., RSAPublicKey interface)
func generateKeyInterface(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~20 lines: interface with Key embed + non-std field getters
}

// generateKeyStruct emits the struct definition + compile-time interface checks + constructor
func generateKeyStruct(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~30 lines: struct fields, var _ assertions, newXxx constructor
}

// generateKeyTypeMethod emits KeyType(), rlock/runlock, IsPrivate
func generateKeyTypeMethods(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~25 lines: KeyType() returns kt.KeyType, lock helpers, IsPrivate bool
}

// generateKeyGetters emits per-field getter methods
func generateKeyGetters(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~40 lines: for each field, emit getter with RLock + nil-check + deref
}

// generateKeyHas emits the Has(name) method
func generateKeyHas(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~20 lines: switch on field names, KeyTypeKey always true
    // Can use shared GenerateHasCases from internal/jwxcodegen
}

// generateKeyFieldAndGet emits Field(name) (any, bool) and Get(name, dst) error methods
func generateKeyFieldAndGet(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~40 lines: Field() is the interface-level accessor (can use shared GenerateFieldCases)
    // Get() is a struct-level convenience wrapper around Field + blackmagic.AssignIfCompatible
}

// generateKeySet emits Set(name, value) and setNoLock(name, value)
func generateKeySet(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~80 lines: the Set wrapper + setNoLock switch
    // Has field-specific overrides for algorithm, keyUsage, hasAccept
    // Can use shared GenerateSetCases with skip-set
}

// generateKeyRemove emits the Remove(key) method
func generateKeyRemove(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~15 lines: switch on field names, nil assignment
    // Can use shared GenerateRemoveCases from internal/jwxcodegen
}

// generateKeyCloneAndCtx emits Clone, DecodeCtx, SetDecodeCtx
func generateKeyCloneAndCtx(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~20 lines: clone delegation, decode context get/set
}

// generateKeyUnmarshalJSON emits UnmarshalJSON with streaming decoder
func generateKeyUnmarshalJSON(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~100 lines: nil fields, optional sensitive field cleanup, streaming decoder
    // Has key-type-specific logic: kty validation, field name prefixing
    // Can partially use shared GenerateUnmarshalJSON
}

// generateKeyMarshalJSON emits MarshalJSON using map + sorted keys + json/v2 encoder
func generateKeyMarshalJSON(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~50 lines: build map[string]any + sorted keys, json.NewEncoder + WriteToken/MarshalEncode
    // Always includes KeyTypeKey, then per-field marshaling with []byte→base64 special case
    // Can use shared GenerateMarshalJSON from internal/jwxcodegen
}

// generateKeyKeys emits the Keys() method
func generateKeyKeys(o *codegen.Output, kt *KeyType, obj *codegen.Object) {
    // ~15 lines: always includes KeyTypeKey, then nil-check iteration
    // Can use shared GenerateKeysMethod from internal/jwxcodegen
}
```

The top-level `generateObject` becomes an orchestrator:

```go
func generateObject(o *codegen.Output, kt *KeyType, obj *codegen.Object) error {
    generateKeyInterface(o, kt, obj)
    generateKeyStruct(o, kt, obj)
    generateKeyTypeMethods(o, kt, obj)
    generateKeyGetters(o, kt, obj)
    generateKeyHas(o, kt, obj)
    generateKeyFieldAndGet(o, kt, obj)
    generateKeySet(o, kt, obj)
    generateKeyRemove(o, kt, obj)
    generateKeyCloneAndCtx(o, kt, obj)
    generateKeyUnmarshalJSON(o, kt, obj)
    generateKeyMarshalJSON(o, kt, obj)
    generateKeyKeys(o, kt, obj)
    return nil
}
```

### Break down `generateGenericHeaders`

This function generates the shared `Key` interface and constants. In v4, the pair pool has been removed (MarshalJSON uses `map[string]any` + sorted keys + json/v2 encoder). Split into:

```go
func generateStdKeyConstants(o *codegen.Output, fields codegen.FieldList)  // const block (KeyTypeKey + std fields)
func generateKeyInterfaceDef(o *codegen.Output, fields codegen.FieldList)  // Key interface definition
```

Note: the per-object function is `generateKeyInterface` (no "Def" suffix) — these have different names to avoid collision.

### Sensitive field handling

`UnmarshalJSON` for private/symmetric keys has a `defer` that clears `[]byte` fields on error. This pattern can be extracted:

```go
// In internal/jwxcodegen:
func GenerateSensitiveFieldCleanup(o *codegen.Output, structName string, fields []codegen.Field) {
    // Emits: defer func() { if retErr != nil { clear(h.field); h.field = nil } }()
    // for all []byte fields
}
```

### Key name prefixing

genjwk has unique logic where non-standard field constants use a key-type prefix (e.g., `RSANKey`, `ECDSAXKey`). The Has/Get/Set/Remove methods must map field names to either `{Name}Key` (standard) or `{Prefix}{Name}Key` (type-specific). This logic stays in genjwk but can be extracted into a helper:

```go
func keyConstantName(f codegen.Field, prefix string) string {
    if f.Bool("is_std") {
        return f.Name(true) + "Key"
    }
    return prefix + f.Name(true) + "Key"
}
```

### `generateStandardFieldsFilterWithFields`

This 54-line function is already well-sized. The inner loop that checks for standard field duplicates can be simplified with a set:

```go
stdSet := make(map[string]struct{}, len(fields))
for _, f := range fields {
    stdSet[f.Name(true)] = struct{}{}
}
```

## Migration

1. Split `generateObject` into the functions listed above
2. Split `generateGenericHeaders` into smaller pieces
3. Replace duplicated helpers with `internal/jwxcodegen` imports
4. Add `direct_storage` to `objects.yml` fields to replace `fieldStorageTypeIsIndirect` logic
5. Verify with `make generate-jwk` that output is unchanged
