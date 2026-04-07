# Refactor genjwt (JWT Token Generator)

## Motivation

`genjwt/main.go` is 727 lines with its core function `generateToken` spanning 529 lines. Like genjwk, it generates interface, struct, constructors, getters, Has, Get, Set, Remove, UnmarshalJSON, MarshalJSON, Keys, and a Claims iterator — all in one function. It also generates a separate `Builder` type.

The generator has unique complexity: it supports multiple packages (`jwt` and `openid`), handles numeric date fields specially (Unix timestamp conversion), has audience flattening logic, and generates a Claims iterator using Go 1.22+ `iter.Seq2`.

## Current Structure

```
_main()                        lines 29-65
  → generateToken(obj)         lines 101-645  (545 lines)
  → genBuilder(obj)            lines 647-727  (81 lines)
```

Helper functions (lines 67-99): `yaml2json`, `IsPointer`, `PointerElem`, `fieldStorageType`, `fieldStorageTypeIsIndirect` — all duplicated from other generators.

## Proposed Changes

### Break down `generateToken` into focused functions

```go
func generateTokenConstants(o *codegen.Output, obj *codegen.Object) {
    // ~15 lines: const block + stdClaimNames array
}

func generateTokenInterface(o *codegen.Output, obj *codegen.Object, pkgPrefix string) {
    // ~40 lines: interface with per-field getters + Field/Set/Has/Remove/Options/Clone/Keys/Claims
}

func generateTokenStruct(o *codegen.Output, obj *codegen.Object, pkgPrefix string) {
    // ~15 lines: struct definition with mu, dc, options, fields, privateClaims
}

func generateTokenConstructor(o *codegen.Output, obj *codegen.Object, pkgPrefix string) {
    // ~20 lines: New() function with privateClaims init + DefaultOptionSet + Options() accessor
}

func generateTokenHas(o *codegen.Output, obj *codegen.Object) {
    // ~15 lines: Has() switch — can use shared GenerateHasCases
}

func generateTokenFieldAndGet(o *codegen.Output, obj *codegen.Object) {
    // ~40 lines: Field(string) (any, bool) is the interface-level accessor (can use shared GenerateFieldCases)
    // Get(string, any) error is a struct-level convenience wrapper using blackmagic.AssignIfCompatible
    // Uses jwterrs.ClaimNotFoundError, ClaimAssignmentFailedError for Get errors
}

func generateTokenRemove(o *codegen.Output, obj *codegen.Object) {
    // ~10 lines: Remove() switch — can use shared GenerateRemoveCases
}

func generateTokenSet(o *codegen.Output, obj *codegen.Object) {
    // ~50 lines: Set() wrapper + setNoLock() switch
    // Field-specific: algorithm (Stringer), hasAccept, type assertion
}

func generateTokenGetters(o *codegen.Output, obj *codegen.Object) {
    // ~40 lines: per-field getter methods with hasGet/indirect/pointer handling
}

func generateTokenPrivateClaims(o *codegen.Output, obj *codegen.Object) {
    // ~5 lines: PrivateClaims() method
}

func generateTokenDecodeCtx(o *codegen.Output, obj *codegen.Object) {
    // ~10 lines: DecodeCtx(), SetDecodeCtx()
}

func generateTokenUnmarshalJSON(o *codegen.Output, obj *codegen.Object) {
    // ~80 lines: streaming JSON decoder with per-type dispatch
    // Uses local+global registry fallback for unknown fields
}

func generateTokenMakePairsAndMarshal(o *codegen.Output, obj *codegen.Object, pkgPrefix string) {
    // ~70 lines: claimPair type, pool, makePairs() with special cases (audience flatten,
    // NumericDate unix, []byte base64), MarshalJSON
}

func generateTokenKeys(o *codegen.Output, obj *codegen.Object) {
    // ~15 lines: Keys() method — can use shared GenerateKeysMethod
}

func generateTokenClaims(o *codegen.Output, obj *codegen.Object) {
    // ~15 lines: Claims() iter.Seq2[string, any] method
}
```

The orchestrator:

```go
func generateToken(obj *codegen.Object) error {
    var buf bytes.Buffer
    o := codegen.NewOutput(&buf)
    // header + package
    pkgPrefix := computePkgPrefix(obj)

    generateTokenConstants(o, obj)
    generateTokenInterface(o, obj, pkgPrefix)
    generateTokenStruct(o, obj, pkgPrefix)
    generateTokenConstructor(o, obj, pkgPrefix)
    generateTokenHas(o, obj)
    generateTokenFieldAndGet(o, obj)
    generateTokenRemove(o, obj)
    generateTokenSet(o, obj)
    generateTokenGetters(o, obj)
    generateTokenPrivateClaims(o, obj)
    generateTokenDecodeCtx(o, obj)
    generateTokenUnmarshalJSON(o, obj)
    generateTokenMakePairsAndMarshal(o, obj, pkgPrefix)
    generateTokenKeys(o, obj)
    generateTokenClaims(o, obj)

    return o.WriteFile(obj.MustString("filename"), codegen.WithFormatCode(true))
}
```

### `genBuilder` stays as-is

At 81 lines, `genBuilder` is already well-sized and self-contained. No changes needed.

### Replace duplicated helpers

`yaml2json`, `IsPointer`, `PointerElem`, `fieldStorageType` move to `internal/jwxcodegen/` (see shared library doc). `fieldStorageTypeIsIndirect` is replaced by `direct_storage` YAML field attribute.

### Field-type-specific marshal strategies

The `makePairs` function has four different marshaling strategies based on field type:

| Field type | Marshal strategy |
|-----------|-----------------|
| `audience` (by name) | `json.MarshalAudience(t.audience, flattenOpt)` |
| `types.NumericDate` | `json.Marshal(t.field.Unix())` |
| `[]byte` | `base64.EncodeToString(t.field)` |
| everything else | `json.Marshal(*(t.field))` |

Note: genjwt is the only v4 generator that still uses the `claimPair` pool + `makePairs()` approach for MarshalJSON. The other three (genjws, genjwe, genjwk) have already migrated to the `map[string]any` + sorted keys + json/v2 encoder pattern. genjwt intentionally keeps its pair-pool pattern and does not use the shared `GenerateMarshalJSON` from `internal/jwxcodegen`.

Since these strategies are JWT-specific and unlikely to be shared, they stay as named cases in `generateTokenMakePairsAndMarshal`. The key improvement is that the function is now ~70 lines instead of buried in a 529-line monolith.

### Multi-package support

The generator supports both `jwt` and `openid` packages via `obj.String("package")`. When the package is not `jwt`, a `pkgPrefix` of `jwt.` is prepended to cross-package type references. This logic is already clean — just extract it into a helper:

```go
func computePkgPrefix(obj *codegen.Object) string {
    if obj.String("package") != "jwt" {
        return "jwt."
    }
    return ""
}
```

## Migration

1. Split `generateToken` into the functions listed above
2. Replace duplicated helpers with `internal/jwxcodegen` imports
3. Add `direct_storage` to `objects.yml` fields where applicable
4. Optionally add `marshal` strategy to YAML config
5. Verify with `make generate-jwt` that output is unchanged
