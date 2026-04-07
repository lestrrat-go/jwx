# Consolidate Generators into a Unified Binary

## Motivation

After Phases 1-3 of the codegen refactoring, the generators share a common library (`internal/jwxcodegen/`) but still exist as 6 separate executables in `tools/cmd/`, each with its own `go.mod`. This means:

1. **6 separate `go.mod` files** that must be kept in sync (dependency versions, Go version, replace directives)
2. **6 separate build steps** — each shell script does `go build` independently
3. **Generator logic is split** between `internal/jwxcodegen/` (shared functions) and `tools/cmd/gen*/` (orchestration) — the library has no way to run on its own

Since all generators already depend on the same `internal/jwxcodegen` module, they should live in the same module as a single binary with subcommands.

## Changes

### New binary: `internal/jwxcodegen/cmd/jwxcodegen/`

Create a single executable that dispatches by subcommand:

```
jwxcodegen generate-jwa    -objects=path/to/objects.yml
jwxcodegen generate-headers -objects=path/to/jws-objects.yml
jwxcodegen generate-jwk    -objects=path/to/objects.yml
jwxcodegen generate-jwt    -objects=path/to/objects.yml
jwxcodegen generate-options -config=path/to/options.yaml
jwxcodegen generate-readfile
```

### File layout

```
internal/jwxcodegen/
  cmd/jwxcodegen/
    main.go            -- subcommand dispatch
    genjwa.go          -- from tools/cmd/genjwa/main.go
    genheaders.go      -- from tools/cmd/genheaders/main.go
    genjwk.go          -- from tools/cmd/genjwk/main.go
    genjwt.go          -- from tools/cmd/genjwt/main.go
    genoptions.go      -- from tools/cmd/genoptions/main.go
    genreadfile.go     -- from tools/cmd/genreadfile/main.go
  config.go            -- shared types (CaseConfig, MethodConfig, etc.)
  comment.go           -- WriteComment
  field.go             -- IsPointer, PointerElem, FieldStorageType, etc.
  genhas.go            -- GenerateHasCases (renamed from gen_has.go)
  genfield.go          -- GenerateFieldCases (renamed from gen_field.go)
  genset.go            -- GenerateSetCases (renamed from gen_set.go)
  genremove.go         -- GenerateRemoveCases (renamed from gen_remove.go)
  genunmarshal.go      -- GenerateUnmarshalCases (renamed from gen_unmarshal.go)
  genmarshal.go        -- GenerateMarshalJSON (renamed from gen_marshal.go)
  genkeys.go           -- GenerateKeysMethod (renamed from gen_keys.go)
  gendecodectx.go      -- GenerateDecodeCtx (renamed from gen_decode_ctx.go)
  genclone.go          -- GenerateCloneFrom (renamed from gen_clone.go)
  yaml.go              -- YAML2JSON
  go.mod
```

File naming convention: `genxxxx.go` (no underscores).

### YAML config locations

YAML config files move from `tools/cmd/gen*/` to the package directories they describe:

| Config | Current location | New location |
|--------|-----------------|--------------|
| JWS header fields | `tools/cmd/genheaders/jws-objects.yml` | `jws/objects.yml` |
| JWE header fields | `tools/cmd/genheaders/jwe-objects.yml` | `jwe/objects.yml` |
| JWK key fields | `tools/cmd/genjwk/objects.yml` | `jwk/objects.yml` |
| JWT token fields | `tools/cmd/genjwt/objects.yml` | `jwt/objects.yml` |
| JWA algorithm types | `tools/cmd/genjwa/objects.yml` | `jwa/objects.yml` |
| JWS options | `jws/options.yaml` | `jws/options.yaml` (unchanged) |
| JWE options | `jwe/options.yaml` | `jwe/options.yaml` (unchanged) |
| JWK options | `jwk/options.yaml` | `jwk/options.yaml` (unchanged) |
| JWT options | `jwt/options.yaml` | `jwt/options.yaml` (unchanged) |
| JWA options | `jwa/options.yaml` | `jwa/options.yaml` (unchanged) |

The `options.yaml` files already live in the package directories. Moving `objects.yml` files there is consistent.

### Shell scripts

Replace per-generator shell scripts with a single `tools/cmd/jwxcodegen.sh` that builds and caches the unified binary:

```bash
#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
EXE="$DIR/.jwxcodegen"

# Build once, reuse
if [ ! -f "$EXE" ]; then
    pushd "$ROOT/internal/jwxcodegen/cmd/jwxcodegen" > /dev/null
    GOWORK=off go build -o "$EXE" .
    popd > /dev/null
fi

"$EXE" "$@"
```

Per-package shell scripts become thin wrappers:

```bash
# tools/cmd/genjws.sh (invoked from jws/ via go:generate)
#!/bin/bash
set -e
echo "Generating JWS files..."
"$(dirname "$0")/jwxcodegen.sh" generate-headers -objects=objects.yml
echo "done!"
```

### Directories to remove

After migration, remove:
- `tools/cmd/genheaders/` (main.go, go.mod, go.sum, jws-objects.yml, jwe-objects.yml)
- `tools/cmd/genjwa/` (main.go, go.mod, go.sum, objects.yml)
- `tools/cmd/genjwk/` (main.go, go.mod, go.sum, objects.yml)
- `tools/cmd/genjwt/` (main.go, go.mod, go.sum, objects.yml)
- `tools/cmd/genoptions/` (main.go, go.mod, go.sum)
- `tools/cmd/genreadfile/` (main.go, go.mod, go.sum)

### `main.go` structure

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Fprintf(os.Stderr, "usage: jwxcodegen <command> [flags]\n")
        os.Exit(1)
    }

    var err error
    switch os.Args[1] {
    case "generate-jwa":
        err = runJWA(os.Args[2:])
    case "generate-headers":
        err = runHeaders(os.Args[2:])
    case "generate-jwk":
        err = runJWK(os.Args[2:])
    case "generate-jwt":
        err = runJWT(os.Args[2:])
    case "generate-options":
        err = runOptions(os.Args[2:])
    case "generate-readfile":
        err = runReadFile(os.Args[2:])
    default:
        fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
        os.Exit(1)
    }

    if err != nil {
        fmt.Fprintf(os.Stderr, "%s\n", err)
        os.Exit(1)
    }
}
```

Each `runXxx` function is in its own file and contains the generator logic currently in `tools/cmd/genXxx/main.go`. The function signature is `func runXxx(args []string) error`, parsing its own flags from the provided args.

### Per-generator changes

**genjwa.go**: Move `_main()`, `Generate()`, `GenerateTest()`, and all helper functions from `tools/cmd/genjwa/main.go`. Rename `_main` to `runJWA`. The `Algorithm`, `Element`, `AlgYAML` types stay local to this file.

**genheaders.go**: Move `_main()`, `generateHeaders()`, `HeaderConfig`, and all helper types/functions from `tools/cmd/genheaders/main.go`. Rename `_main` to `runHeaders`.

**genjwk.go**: Move `_main()`, `generateObject()`, `generateGenericHeaders()`, `KeyType`, and all helper functions from `tools/cmd/genjwk/main.go`. Rename `_main` to `runJWK`.

**genjwt.go**: Move `_main()`, `generateToken()`, `genBuilder()`, and all helper functions from `tools/cmd/genjwt/main.go`. Rename `_main` to `runJWT`.

**genoptions.go**: Move `_main()`, `genOptions()`, `genOptionTests()` from `tools/cmd/genoptions/main.go`. Rename `_main` to `runOptions`.

**genreadfile.go**: Move `_main()` and `definition` type from `tools/cmd/genreadfile/main.go`. Rename `_main` to `runReadFile`.

### go.mod changes

The `internal/jwxcodegen/go.mod` already exists. Add the `cmd/jwxcodegen` binary to it — no new module needed since it's inside the same module tree. The existing dependencies (`github.com/lestrrat-go/codegen`, `github.com/goccy/go-yaml`) cover all generators except:

- `genjwt` uses `github.com/goccy/go-json` — add to `go.mod`
- `genoptions` uses `github.com/lestrrat-go/xstrings` — add to `go.mod`

### Makefile changes

The `generate-%` pattern rule uses `go generate $(pwd)/$(pkg)`, which runs the `//go:generate` directive in each package. The directives change to invoke the unified shell script:

```
//go:generate ../tools/cmd/genjws.sh
```

The shell scripts are thin wrappers around `jwxcodegen.sh`, so the Makefile itself doesn't change.

### Migration

1. Rename shared library files: `gen_xxx.go` → `genxxx.go`
2. Create `internal/jwxcodegen/cmd/jwxcodegen/main.go` with subcommand dispatch
3. Move each generator's logic into `cmd/jwxcodegen/genXxx.go`
4. Move YAML config files to package directories
5. Update `internal/jwxcodegen/go.mod` with additional dependencies
6. Create `tools/cmd/jwxcodegen.sh` builder script
7. Update per-package shell scripts to use `jwxcodegen.sh`
8. Update `//go:generate` directives if needed
9. Remove `tools/cmd/gen*/` directories
10. Verify: `make generate` produces identical output
