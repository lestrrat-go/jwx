# stdlib Modernization

## Motivation

Replace older stdlib patterns with modern equivalents available in Go 1.21+.

## Changes

### sort → slices

All `sort.Slice` / `sort.Strings` calls in library code and generated code replaced with `slices.SortFunc` / `slices.Sort`.

| Location | Before | After |
|----------|--------|-------|
| Generated MarshalJSON (all packages) | `sort.Slice(fields, ...)` | `slices.SortFunc(fields, ...)` |
| Generated JWA algorithm lists | `sort.Slice(list, ...)` | `slices.SortFunc(list, ...)` |
| `jwk/set.go` | `sort.Strings(fields)` | `slices.Sort(fields)` |
| `jwe/message.go` | `sort.Slice(fields, ...)` | `slices.SortFunc(fields, ...)` |
| `cmd/jwx/jwx.go` | `sort.Slice(commands, ...)` | `slices.SortFunc(commands, ...)` |

### goccy/go-json dependency removed

`github.com/goccy/go-json` removed from `go.mod`. The `jwx_goccy` build tag is no longer supported. `encoding/json/v2` replaces both the stdlib and goccy backends.

### go.mod

- `go` directive bumped from `1.25.0` to `1.26.0`
- `github.com/goccy/go-json` removed from `require`

### Makefile

- `GOEXPERIMENT=jsonv2` exported globally
- Removed targets: `test-goccy`, `test-stdlib`, `cover-goccy`, `cover-stdlib`, `smoke-goccy`, `smoke-stdlib`
- `test` target runs directly (no goccy/stdlib distinction)

### Build tags

| Tag | Status |
|-----|--------|
| `jwx_goccy` | Removed |
| `jwx_es256k` | Unchanged |
| `jwx_secp256k1_pem` | Unchanged |
| `jwx_asmbase64` | Unchanged |
