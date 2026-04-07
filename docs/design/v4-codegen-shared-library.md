# Shared Code Generation Library

## Motivation

The four "object" generators (`genjwt`, `genjws`, `genjwe`, `genjwk`) were developed independently, each copy-pasting the same helper functions and generation patterns. This has led to:

1. **5 identical copies** of `yaml2json`, `IsPointer`, `PointerElem`, `fieldStorageType`
2. **4 divergent copies** of `fieldStorageTypeIsIndirect`, each hardcoding type-specific knowledge that should be declarative
3. **Duplicated generation patterns** (Has/Field/Set/Remove methods, UnmarshalJSON decoder loop, MarshalJSON with map+sorted keys, Keys() iteration, cloneFrom) repeated across generators with minor variations
4. **No shared test infrastructure** — zero tests for any generator

## Changes

### New module: `internal/jwxcodegen/`

Create `internal/jwxcodegen/go.mod` as a standalone module. The `internal/` prefix makes it invisible to library consumers. The package name is `jwxcodegen` (not `codegen`) to avoid collision with the existing `github.com/lestrrat-go/codegen` dependency.

Go's `internal` package restriction allows imports from modules whose paths share the parent prefix. To satisfy this, **all generator module paths must be standardized** under the same root (see "Generator module path cleanup" below). Each generator adds a `replace` directive:

```
// in tools/cmd/genjwt/go.mod
module github.com/lestrrat-go/jwx/v4/tools/cmd/genjwt

require github.com/lestrrat-go/jwx/v4/internal/jwxcodegen v0.0.0

replace github.com/lestrrat-go/jwx/v4/internal/jwxcodegen => ../../../internal/jwxcodegen
```

### Generator module path cleanup

The original generator module paths were inconsistent (v3 paths, one had a typo `gitub`). In Phases 2-3 they were standardized to `github.com/lestrrat-go/jwx/v4/tools/cmd/{name}`. In Phase 4, all generators move into the `internal/jwxcodegen` module, eliminating the separate `go.mod` files entirely. See `v4-codegen-unified-binary.md`.

### Package layout

```
internal/jwxcodegen/
  go.mod
  yaml.go          -- YAML2JSON
  field.go         -- IsPointer, PointerElem, FieldStorageType, FieldStorageTypeIsIndirect
  config.go        -- CaseConfig, MethodConfig, MarshalConfig, KeysConfig, CloneConfig
  genhas.go        -- GenerateHasCases (case clauses only)
  genfield.go      -- GenerateFieldCases (case clauses only)
  genset.go        -- GenerateSetCases (case clauses only)
  genremove.go     -- GenerateRemoveCases (case clauses only)
  genunmarshal.go  -- GenerateUnmarshalCases (case clauses only)
  genmarshal.go    -- GenerateMarshalJSON (full method — no special cases across generators)
  genkeys.go       -- GenerateKeysMethod (full method — no special cases across generators)
  gendecodectx.go  -- GenerateDecodeCtx / GenerateSetDecodeCtx (full methods)
  genclone.go      -- GenerateCloneFrom (full method)
  comment.go       -- WriteComment (moved from genoptions)
  cmd/jwxcodegen/  -- unified binary (see v4-codegen-unified-binary.md)
    main.go        -- subcommand dispatch
    genjwa.go      -- JWA algorithm generation
    genheaders.go  -- JWS/JWE header generation
    genjwk.go      -- JWK key generation
    genjwt.go      -- JWT token generation
    genoptions.go  -- options generation
    genreadfile.go -- ReadFile generation
```

Naming convention: functions that emit case clauses for a switch (where callers may need to add their own special cases) are named `Generate*Cases`. Functions that emit a complete method (where no caller needs to customize) are named `Generate*Method` or `Generate*`.

Dependencies: `github.com/lestrrat-go/codegen`, `github.com/goccy/go-yaml`.

### Extracting identical helpers

These move verbatim into `internal/jwxcodegen/`:

```go
// yaml.go
func YAML2JSON(fn string) ([]byte, error) { ... }

// field.go
func IsPointer(f codegen.Field) bool {
    return strings.HasPrefix(f.Type(), "*")
}

func PointerElem(f codegen.Field) string {
    return strings.TrimPrefix(f.Type(), "*")
}

func FieldStorageType(f codegen.Field) string {
    if FieldStorageTypeIsIndirect(f) {
        return "*" + f.Type()
    }
    return f.Type()
}
```

### Eliminating `fieldStorageTypeIsIndirect` divergence

Currently each generator hardcodes which types are stored directly vs indirectly:

| Generator | Direct storage types (NOT wrapped in `*`) |
|-----------|------------------------------------------|
| genjwt | `*`-prefixed, `[]`-prefixed, `List`-suffixed |
| genjws | `*`-prefixed, `[]`-prefixed, `jwk.Key` |
| genjwe | `*`-prefixed, `[]`-prefixed, `jwk.Key`, `jwk.ECDSAPublicKey` |
| genjwk | `*`-prefixed, `[]`-prefixed, `List`-suffixed (except `KeyOperationList`) |

**Proposed fix**: Add a `direct_storage` boolean field to the YAML config. When `direct_storage: true`, the field is stored as-is (no pointer wrapping). The default (`false` / omitted) means indirect storage (pointer-wrapped).

This moves type knowledge from Go code into the YAML where it belongs. The shared `FieldStorageTypeIsIndirect` function becomes:

```go
func FieldStorageTypeIsIndirect(f codegen.Field) bool {
    if f.Bool("direct_storage") {
        return false
    }
    return !(strings.HasPrefix(f.Type(), "*") || strings.HasPrefix(f.Type(), "[]"))
}
```

The `List`-suffix heuristic and per-type exceptions (`jwk.Key`, `KeyOperationList`) are replaced by explicit `direct_storage: true` annotations on the relevant fields in `objects.yml`.

Note: genjwe's `fieldStorageTypeIsIndirect` lists `jwk.ECDSAPublicKey` as a direct-storage type, but no field in `genjwe/objects.yml` actually uses that type. It is dead code.

#### Exact fields requiring `direct_storage: true`

| File | Field | Type | Why |
|------|-------|------|-----|
| `genjws/objects.yml` | `jwk` | `jwk.Key` | Interface type, already a pointer |
| `genjwe/objects.yml` | `ephemeralPublicKey` | `jwk.Key` | Interface type, already a pointer |
| `genjwe/objects.yml` | `jwk` | `jwk.Key` | Interface type, already a pointer |
| `genjwt/objects.yml` | `audience` | `types.StringList` | Slice type (aliased), stored directly |

`genjwk/objects.yml` `keyOps` (`KeyOperationList`) does NOT get `direct_storage: true` — it is the exception that IS stored indirectly despite ending in "List".

### Common generation patterns

Each pattern becomes a function that takes `*codegen.Output`, field metadata, and configuration. The generator calls these instead of inlining the logic.

**GenerateHasCases** — case clauses for the Has() switch on field names. Takes: output, fields, key-name function, optional extra cases (e.g., genjwk's `KeyTypeKey: return true`).

**GenerateFieldCases** — case clauses for the `Field(string) (any, bool)` switch. This is the v4 interface-level accessor used by all four generators. Takes: output, fields, key-name function, per-field config for indirect deref.

Note: the old `Get(string, any) error` still exists as a struct-level convenience method on genjwt and genjwk, but it is no longer part of any interface. Each generator that needs it can emit it locally — it's a thin wrapper around `Field` + `blackmagic.AssignIfCompatible` and doesn't warrant a shared function.

**GenerateSetCases** — case clauses for the setNoLock() switch with type assertions and Accept pattern. Takes: output, fields, key-name function, skip set for fields with custom handling.

**GenerateRemoveCases** — case clauses for the Remove() switch. Takes: output, fields, key-name function.

**GenerateUnmarshalCases** — case clauses for the json/v2 streaming decoder's inner switch, dispatching per-type decode (string via `AssignNextStringToken`, bytes via `AssignNextBytesToken`, slice/struct via `json.UnmarshalDecode`, jwk.Key via `jwk.ParseKey`). Takes: output, fields, key-name function, skip set. The caller owns the outer `ReadToken`/`PeekKind` loop, the opening/closing brace consumption, the `default:` registry fallback, and any pre/post logic (sensitive field cleanup, kty validation, `h.raw = buf`, etc.).

**GenerateMarshalJSON** — the v4 pattern: build `map[string]any` + `[]string` keys under RLock, `slices.Sort(keys)`, then `json.NewEncoder(buf)` with `enc.WriteToken(jsontext.BeginObject)`, per-key `enc.WriteToken(jsontext.String(k))` + `json.MarshalEncode(enc, v)`, with `[]byte` special-cased to `base64.EncodeToString`. Takes: output, struct name, fields, private params field name, optional always-present entries (e.g., genjwk's `KeyTypeKey`).

Note: genjwt still uses a `claimPair` pool + `makePairs()` approach for marshaling. This is intentionally not migrated; genjwt does not use the shared `GenerateMarshalJSON`.

**GenerateKeysMethod** — the Keys() method with nil-check iteration + private params. Takes: output, struct name, fields, private params field name, optional always-present keys.

**GenerateCloneFrom** — the `cloneFrom(src)` method with per-field nil-check, deep copy for slices via `slices.Clone`, pointer deref copy for indirect types. Takes: output, struct name, fields, private params field name, extra fields to clone (e.g., `raw`).

These are not abstract interfaces — they are plain functions that call `o.L()` / `o.R()`. Each generator composes them with its own field-specific configuration. The goal is eliminating copy-paste, not creating an over-engineered framework.

### Per-field special cases

Several generators have field-specific branches in Set/UnmarshalJSON (e.g., `algorithm` gets `jwa.KeyAlgorithmFrom`, `contentEncryption` gets an empty check, `keyUsage` gets enum validation). These are handled with a **skip-set approach**: the shared function accepts a `skip` set of field names it should not emit code for, and the caller handles those fields separately before or after calling the shared function.

The shared functions emit **only `case` clauses**, not the `switch` wrapper. This lets the caller interleave its special cases in the same switch:

```go
// Caller (e.g., genjws setNoLock):
o.L("switch name {")
o.L("case AlgorithmKey:")           // special case, handled inline
o.L("  alg, err := jwa.KeyAlgorithmFrom(value)")
o.L("  // ...")
jwxcodegen.GenerateSetCases(o, cfg, skip)  // emits remaining case clauses
o.L("default:")
o.L("  h.privateParams[name] = value")
o.L("}")
```

```go
// Shared function emits only case clauses, not the switch:
func GenerateSetCases(o *codegen.Output, cfg SetConfig, skip map[string]struct{}) {
    for _, f := range cfg.Fields {
        if _, ok := skip[f.Name(false)]; ok {
            continue
        }
        o.L("case %s:", cfg.KeyName(f))
        // default set logic for this field
    }
}
```

All `Generate*` shared functions follow this pattern: emit case clauses only. The caller owns the switch/default/closing brace. This keeps special-case logic visible at the call site.

### Migration path

Four phases, each independently committable and verifiable with `make generate` + diff:

**Phase 1: Split monolithic functions** (no shared code, no YAML changes) — DONE
1. Break down `generateObject` (genjwk), `generateToken` (genjwt), `Generate`/`GenerateTest` (genjwa), as described in per-tool design docs
2. Unify genjws/genjwe into genheaders (header generators doc)
3. Verify: `make generate` produces identical output

**Phase 2: Create shared library and migrate** — DONE
1. Create `internal/jwxcodegen/` module with shared helpers (`YAML2JSON`, `IsPointer`, `PointerElem`, `FieldStorageType`, `FieldStorageTypeIsIndirect`, `WriteComment`)
2. Create shared generation functions (`GenerateHasCases`, `GenerateFieldCases`, `GenerateSetCases`, etc.)
3. Standardize generator module paths to `github.com/lestrrat-go/jwx/v4/tools/cmd/{name}`
4. Update each `tools/cmd/gen*/go.mod` to add dependency + replace directive
5. Replace local helpers and inline generation blocks with calls to `internal/jwxcodegen`
6. Verify: `make generate` produces identical output

**Phase 3: YAML schema migration** — DONE
1. Add `direct_storage` annotations to YAML configs (see exact field table above)
2. Remove `fieldStorageTypeIsIndirect` from generators (replaced by `FieldStorageTypeIsIndirect` in shared library)
3. Add `ident_name` to genoptions YAML, remove `WithCompact` hardcoded check
4. Verify: `make generate` produces identical output

**Phase 4: Consolidate into unified binary** — see `v4-codegen-unified-binary.md`
1. Rename shared library files: `gen_xxx.go` → `genxxx.go`
2. Create `internal/jwxcodegen/cmd/jwxcodegen/` with subcommand dispatch
3. Move generator logic from `tools/cmd/gen*/main.go` into `cmd/jwxcodegen/genXxx.go`
4. Move YAML config files to package directories
5. Update shell scripts and remove `tools/cmd/gen*/` directories
6. Verify: `make generate` produces identical output

**Important**: YAML config changes and corresponding generator code changes must be committed together. Running an old generator against new YAML silently ignores new fields (e.g., `direct_storage: true` would be ignored, causing the field to be pointer-wrapped incorrectly).
