# Unify genjws and genjwe Header Generators

## Motivation

`genjws/main.go` (486 lines) and `genjwe/main.go` (479 lines) are nearly identical. Both generate a `Headers` interface, `stdHeaders` struct, and the same set of methods (getters, Has, Field, Set, Remove, UnmarshalJSON, MarshalJSON, Keys, cloneFrom). The code was copy-pasted and diverged only where JWS and JWE semantics differ.

Maintaining two ~500-line files that are 90%+ identical means every fix or improvement must be applied twice, and the copies drift further apart over time (they already have minor inconsistencies).

## Catalog of Actual Differences

### 1. Package and comments
- **genjws**: `package jws`, references RFC 7515
- **genjwe**: `package jwe`, references RFC 7516

### 2. Imports
- **genjwe**: has explicit `o.WriteImports(...)` listing cert, base64, json, pool, tokens, jwa, jwk
- **genjws**: does not emit explicit imports (relies on goimports)

### 3. Interface getter return types
- **genjws**: checks `f.Bool("noDeref")` to decide whether to return pointer or element type
- **genjwe**: always returns `f.Type()`

### 4. Extra interface methods
- **genjws**: `Copy(Headers) error`, `Merge(Headers) (Headers, error)`, `Clone() (Headers, error)`
- **genjwe**: same plus `Encode() ([]byte, error)`, `Decode([]byte) error`

### 5. Struct extra fields
- **genjws**: `dc DecodeCtx`, `raw []byte` (stores raw header for signature verification)
- **genjwe**: neither

### 6. NewHeaders initialization
- **genjws**: `return &stdHeaders{}`
- **genjwe**: `return &stdHeaders{privateParams: map[string]any{}}`

### 7. JWS-only methods
- `DecodeCtx() DecodeCtx`
- `SetDecodeCtx(dc DecodeCtx)`
- `rawBuffer() []byte`

### 8. Getter implementation (BUG)
- **genjws**: indirect fields get nil-check → deref; direct fields `return h.%s, true`
- **genjwe**: indirect fields same; direct fields `return h.%[1]s, h.%[1]s!=nil`

This is a **bug**: for non-nillable direct-storage types, genjws always returns `true` while genjwe checks for nil. The genjws behavior is correct for interface types like `jwk.Key` (which CAN be nil). The genjwe format happens to produce the same result in practice since all current direct-storage fields are interface types, but the `true` variant in genjws is semantically clearer. The unified generator should use the genjws pattern.

### 9. Algorithm Set handler
- **genjws**: hardcoded `Algorithm` field name → `jwa.KeyAlgorithmFrom(value)` → cast to `jwa.SignatureAlgorithm`
- **genjwe**: no special case for Algorithm (uses default type-assertion path for `jwa.KeyEncryptionAlgorithm` — the field does NOT have `hasAccept`)

### 10. Content encryption empty check
- **genjwe**: `contentEncryption` field gets an empty-value rejection check
- **genjws**: no equivalent

### 11. fieldStorageTypeIsIndirect
- **genjws**: `!(s == "jwk.Key" || strings.HasPrefix(s, "*") || strings.HasPrefix(s, "[]"))`
- **genjwe**: `!(s == "jwk.Key" || s == "jwk.ECDSAPublicKey" || strings.HasPrefix(s, "*") || strings.HasPrefix(s, "[]"))`

Note: `jwk.ECDSAPublicKey` in genjwe is dead code — no field in genjwe's objects.yml uses that type. Replaced by `direct_storage` YAML attribute (see shared library doc).

### 12. cloneFrom
- **genjws**: also clones `raw` field, sets `dst.privateParams = nil` when empty
- **genjwe**: no `raw` field, sets `dst.privateParams = map[string]any{}` when empty

The unified generator should use `nil` for empty privateParams (genjws pattern). An empty map and nil are semantically equivalent for all consumers (Has/Get/Set all handle nil privateParams). Using `nil` avoids an unnecessary allocation.

### 13. clear()
- **genjws**: `clear()` is a non-locking helper called from UnmarshalJSON (which holds the lock). Also nils `raw`.
- **genjwe**: `clear()` acquires its own lock. Also resets `privateParams` to empty map.

The unified generator should use the lock-free pattern (genjws). `clear()` is only called from `UnmarshalJSON`, which already holds the write lock. Acquiring it again would deadlock with `sync.Mutex` or be unnecessary overhead with `sync.RWMutex`.

### 14. UnmarshalJSON
- **genjws**: calls `h.clear()` then decodes
- **genjwe**: nils fields inline then decodes (no `clear()` call)
- After decode, **genjws**: `h.raw = buf`, **genjwe**: nothing

## Proposed Changes

### Single unified generator: `tools/cmd/genheaders/`

Replace both `genjws/` and `genjwe/` with a single `genheaders/` tool that reads a config specifying the per-package differences.

### Extended YAML config

Each package's `objects.yml` gains top-level metadata:

```yaml
package: jws
generator_comment: "tools/cmd/genheaders/main.go"
output_file: headers_gen.go
rfc: "RFC 7515"
description: "JWS Header"

# Extra interface methods beyond the standard set
extra_interface_methods:
  - "Copy(Headers) error"
  - "Merge(Headers) (Headers, error)"
  - "Clone() (Headers, error)"

# Extra struct fields beyond the standard set
extra_struct_fields:
  - name: dc
    type: DecodeCtx
  - name: raw
    type: "[]byte"
    comment: "stores the raw version of the header so it can be used later"

# Whether NewHeaders initializes privateParams
init_private_params: false

# Whether to store raw buffer after unmarshal
store_raw_on_unmarshal: true

# Extra generated methods (each tied to a struct field above)
extra_methods:
  - method: DecodeCtx
    field: dc
    returns: DecodeCtx
  - method: SetDecodeCtx
    field: dc
    arg: "dc DecodeCtx"
  - method: rawBuffer
    field: raw
    returns: "[]byte"

fields:
  - name: algorithm
    # ... existing field definition ...
```

The differences from the catalog above map to config flags:
- Differences 1-2: `package`, `generator_comment`
- Difference 3: `getter_returns_type` field attribute (replaces `noDeref` check divergence)
- Difference 4: `extra_interface_methods`
- Difference 5: `extra_struct_fields`
- Difference 6: `init_private_params`
- Difference 7: `extra_methods`
- Differences 9-10: handled via skip-set in the shared generation functions (see shared library doc)
- Difference 11: `direct_storage` field attribute (see shared library doc)
- Differences 12-14: `store_raw_on_unmarshal`, `init_private_params`

### Generator structure

```go
// tools/cmd/genheaders/main.go

type ExtraMethod struct {
    Method  string // method name
    Field   string // struct field it reads/writes
    Returns string // return type (empty for setters)
    Arg     string // argument (empty for getters)
}

type HeaderConfig struct {
    Package              string
    GeneratorComment     string
    OutputFile           string
    RFC                  string
    Description          string
    ExtraInterfaceMethods []string
    ExtraStructFields    []StructField
    InitPrivateParams    bool
    StoreRawOnUnmarshal  bool
    ExtraMethods         []ExtraMethod
    Fields               codegen.FieldList
}

func _main() error {
    cfg := loadConfig(*objectsFile) // reads YAML into HeaderConfig
    return generateHeaders(cfg)
}

func generateHeaders(cfg *HeaderConfig) error {
    // Uses shared library functions from internal/jwxcodegen
    // for Has, Field, Set, Remove, UnmarshalJSON, MarshalJSON, Keys
    // Conditionally generates extra methods based on config
}
```

### Shell script changes

Replace `genjws.sh` and `genjwe.sh` with a single `genheaders.sh` that runs the tool twice:

```bash
EXE="${DIR}/.genheaders"
"$EXE" -objects="$DIR/jws-objects.yml"
"$EXE" -objects="$DIR/jwe-objects.yml"
```

Or keep the existing per-package `go:generate` directives and just change which binary they invoke.

### Migration

1. Create `tools/cmd/genheaders/` with the unified generator
2. Move `genjws/objects.yml` → `tools/cmd/genheaders/jws-objects.yml` (with new metadata fields)
3. Move `genjwe/objects.yml` → `tools/cmd/genheaders/jwe-objects.yml` (with new metadata fields)
4. Update Makefile `generate-jws` and `generate-jwe` targets
5. Remove `tools/cmd/genjws/` and `tools/cmd/genjwe/`
6. Update `//go:generate` directives in `jws/` and `jwe/` package source files to invoke `genheaders` instead of the old binaries
7. Verify `make generate` produces identical output
