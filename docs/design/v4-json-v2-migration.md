# encoding/json/v2 Migration

## Motivation

v3 maintained a build-tag abstraction (`internal/json/`) to switch between `encoding/json` and `goccy/go-json`. This added complexity and two parallel code paths. Go 1.26 ships `encoding/json/v2` (behind `GOEXPERIMENT=jsonv2`) which is performance-competitive with goccy, making the abstraction unnecessary.

## Changes

### internal/json/

- Deleted `stdlib.go` and `goccy.go` (build-tag files).
- Single `json.go` imports `encoding/json/v2` and `encoding/json/jsontext`.
- Type aliases: `Decoder = jsontext.Decoder`, `Encoder = jsontext.Encoder`, `RawMessage = jsontext.Value`.
- Removed: `Delim`, `Number`, `Marshaler`, `Unmarshaler` type aliases.
- Replaced: `DecoderSettings()` → `SetUseNumber()`/`GetUseNumber()` (global atomic bool).
- Added: `MarshalEncode()`, `UnmarshalDecode()` wrappers.
- Helper functions (`AssignNextBytesToken`, `ReadNextStringToken`, etc.) adapted to use `jsontext.Decoder` API (`ReadToken()`, `PeekKind()`) instead of `json.Decoder` API (`Token()`, `Decode()`).

### internal/json/registry.go

- `Registry.Decode` signature changed from `(dec *Decoder, name string)` to `(name string, raw RawMessage)`. Callers read the raw value from the decoder first, then pass it.
- Added generic `TypedDecoder[T]` and `RegisterTyped[T]()` to replace reflect-based `objectTypeDecoder`.
- Kept `objectTypeDecoder` for backward compat with `Register(name, object any)`.

### Code generators (genjwt, genjws, genjwe, genjwk)

UnmarshalJSON templates changed:
- `dec.Token()` loop with `json.Delim` type switch → `dec.ReadToken()` / `dec.PeekKind()` loop with `tok.Kind()` checks
- `dec.Decode(&val)` → `json.UnmarshalDecode(dec, &val)`
- Unknown fields: `dec.ReadValue()` then `registry.Decode(fieldName, raw)`

MarshalJSON templates changed:
- Manual byte-buffer construction → `jsontext.Encoder` with `WriteToken()` / `MarshalEncode()`
- `sort.Slice` → `slices.SortFunc`

### Removed APIs

| Removed | Replacement |
|---------|-------------|
| `jwx.DecoderSettings()` | `jwx.Settings()` |
| `jwx.WithUseNumber()` | `jwx.WithUseNumber()` (same name, works with `jwx.Settings`) |
| `json.Number` type | `encoding/json.Number` (available when `jwx.WithUseNumber(true)` is set) |
| `json.Delim` type | `jsontext.Kind` constants (`'{'`, `'}'`, etc.) |
| `jwx_goccy` build tag | Removed entirely |

### Build requirements

During development: `GOEXPERIMENT=jsonv2` must be set for all `go build`, `go test`, `go generate` commands. The Makefile exports this automatically.

v4 will ship when json/v2 graduates to default in a future Go release.

## Migration guide (v3 → v4)

```go
// v3
jwx.DecoderSettings(jwx.WithUseNumber(true))

// v4
jwx.Settings(jwx.WithUseNumber(true))
```

```go
// v3
var n json.Number
token.Get("custom-num", &n)

// v4 (with UseNumber enabled)
n, err := jwt.Get[json.Number](token, "custom-num")

// v4 (without UseNumber — default)
f, err := jwt.Get[float64](token, "custom-num")
```
