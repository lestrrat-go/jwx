# AGENTS.md

## For Module Consumers

If you are writing code that *uses* jwx (not developing jwx itself):

- **Examples**: See [`github.com/jwx-go/examples`](https://github.com/jwx-go/examples) for runnable usage patterns (locally at `examples/` when checked out via `go.work`)
- **Documentation**: See `docs/` directory and package READMEs
- **API Reference**: Use `go doc` or https://pkg.go.dev/github.com/lestrrat-go/jwx/v4
- **Migrating from v3?** See [`MIGRATION.md`](MIGRATION.md) for a complete guide, and [`github.com/jwx-go/jwxmigrate`](https://github.com/jwx-go/jwxmigrate) for machine-readable migration rules and automated checking

The rest of this document focuses on developing the jwx library itself.

---

## Go Version

This project requires **Go 1.26.0** or later. Check `go.mod` for the exact version.

## GOEXPERIMENT

v4 depends on `encoding/json/v2` which requires `GOEXPERIMENT=jsonv2`. The Makefile exports this automatically, but any direct `go build`, `go test`, or `go run` invocation **must** set it:

```bash
GOEXPERIMENT=jsonv2 go test ./...
GOEXPERIMENT=jsonv2 go build ./...
```

Without this, builds fail with `build constraints exclude all Go files` errors.

## Module Path vs Physical Layout

This repository uses a **flat layout** with vanity import paths. There is no physical `v4/` directory.

| Branch | Module Path | Physical Root |
|--------|-------------|---------------|
| `develop/v4` | `github.com/lestrrat-go/jwx/v4` | `/` (repo root) |

`import "github.com/lestrrat-go/jwx/v4/jwt"` → files are at `./jwt/`, not `./v4/jwt/`.

## Code Generation

### Immutable Rule

**NEVER edit files ending in `_gen.go` directly.** These are generated files. Edit the generator sources instead.

### Generated Files Pattern

Files matching `*_gen.go` are generated. Examples:
- `jwt/options_gen.go`
- `jwt/token_gen.go`
- `jws/headers_gen.go`
- `jwk/rsa_gen.go`
- `jwa/signature_gen.go`

### Generator Locations

All generators live in a single binary at `internal/jwxcodegen/cmd/jwxcodegen/`. Each is invoked via subcommand through `scripts/jwxcodegen.sh`, which builds and caches the binary. The `//go:generate` directives in each package call `scripts/jwxcodegen.sh` directly.

| Generator | Subcommand | Input Files | Output |
|-----------|------------|-------------|--------|
| `genoptions` | `generate-options` | `{jwa,jwe,jwk,jws,jwt}/options.yaml` | `*/options_gen.go` |
| `genjwt` | `generate-jwt` | `jwt/objects.yml` | `jwt/*_gen.go` |
| `genheaders` | `generate-headers` | `jws/objects.yml` | `jws/headers_gen.go` |
| `genheaders` | `generate-headers` | `jwe/objects.yml` | `jwe/headers_gen.go` |
| `genjwk` | `generate-jwk` | `jwk/objects.yml` | `jwk/*_gen.go` |
| `genjwa` | `generate-jwa` | `jwa/objects.yml` | `jwa/*_gen.go` |
| `genreadfile` | `generate-readfile` | - | ReadFile helpers |

### Regeneration Commands

```bash
# Regenerate all code (includes options via `go generate .`)
make generate

# Regenerate specific package (objects/types only, NOT options)
make generate-jwt
make generate-jws
make generate-jwe
make generate-jwk
make generate-jwa

# Regenerate options only (options.yaml → options_gen.go for all packages)
go generate .
# or directly:
./scripts/jwxcodegen.sh generate-all-options
```

**Important:** `make generate-<pkg>` does **not** regenerate options. If you
edit an `options.yaml` file, run `make generate` or `go generate .`.

## Functional Options Pattern

Options are defined in `{package}/options.yaml` and generated into `{package}/options_gen.go`.

Example `options.yaml` entry:

```yaml
options:
  - ident: Token
    interface: ParseOption
    argument_type: Token
    comment: |
      WithToken specifies the token instance...
```

Generates `WithToken(v Token) ParseOption` function.

## Multi-Module Structure

This repository contains multiple Go modules. The nested modules use `replace` directives for local development.

| Module | Path | Purpose |
|--------|------|---------|
| Main | `./go.mod` | Core library |
| Examples | [`github.com/jwx-go/examples`](https://github.com/jwx-go/examples) | Usage examples (external repo, local at `./examples/` via `go.work`) |
| CLI | `./cmd/jwx/go.mod` | Command-line tool |
| Generators | `./internal/jwxcodegen/go.mod` | Code generators |

Benchmarks live in a separate repository: [github.com/jwx-go/benchmarks](https://github.com/jwx-go/benchmarks).

### Local Development

No `go.work` file is committed. When working across modules (including examples and extensions), create a temporary `go.work` file (it is .gitignored). If a `go.work` file is present, read it to discover local paths to companion modules (extensions, examples, etc.).

## Development Commands

```bash
# Run all tests
make test

# Run short/smoke tests
make smoke

# Generate coverage report
make cover
make viewcover

# Lint
make lint

# Format and tidy
make imports
make tidy
```

### Test Script Details

Tests are run via `./scripts/test.sh` which iterates over:
- `.` (main module)
- `./cmd/jwx`

## Package Directory Map

| Package | Responsibility |
|---------|----------------|
| `jwa/` | Algorithm identifiers (e.g., `RS256`, `ES384`, `A128GCM`) |
| `jwk/` | JSON Web Keys - key representation and management |
| `jws/` | JSON Web Signatures - `Sign()` and `Verify()` |
| `jwe/` | JSON Web Encryption - `Encrypt()` and `Decrypt()` |
| `jwt/` | JSON Web Tokens - claims and validation |
| `jwt/openid/` | OpenID Connect ID tokens |

## Relevant RFCs

- RFC 7515 - JWS (JSON Web Signature)
- RFC 7516 - JWE (JSON Web Encryption)
- RFC 7517 - JWK (JSON Web Key)
- RFC 7518 - JWA (JSON Web Algorithms)
- RFC 7519 - JWT (JSON Web Token)
- OpenID Connect Core 1.0

## Error Handling

JWT error types are struct types. Use zero-value structs with `errors.Is()`, or `errors.AsType[T]()` for structured fields:

```go
if errors.Is(err, jwt.TokenExpiredError{}) { ... }

if expErr, ok := errors.AsType[jwt.TokenExpiredError](err); ok {
    log.Printf("expired at %s", expErr.Expiration)
}
```

| Package | Type / Function | Meaning |
|---------|----------------|---------|
| `jwt` | `TokenExpiredError{}` | `exp` claim not satisfied |
| `jwt` | `TokenNotYetValidError{}` | `nbf` claim not satisfied |
| `jwt` | `InvalidIssuerError{}` | `iss` claim not satisfied |
| `jwt` | `InvalidAudienceError{}` | `aud` claim not satisfied |
| `jwt` | `ValidationError{}` | Generic validation failure |
| `jwt` | `ParseError{}` | Parse failed |
| `jws` | `VerificationError()` | Signature verification failed |
| `jwe` | `DecryptError()` | Decryption failed |

## Testing

Use `github.com/stretchr/testify/require` for assertions (not `assert`).

## Build Tags

No build tags in v4. Optional features (signature algorithms, backend replacements) are provided as extension modules under [`github.com/jwx-go`](https://github.com/jwx-go). See [Extension Modules](docs/10-extensions.md) for the full list.

## Quick Reference: Common Modifications

| Task | Edit This | Then Run |
|------|-----------|----------|
| Add/edit any option | `{pkg}/options.yaml` | `make generate` or `go generate .` |
| Add new JWS header field | `jws/objects.yml` | `make generate-jws` |
| Add new JWE header field | `jwe/objects.yml` | `make generate-jwe` |
| Add new JWK key field | `jwk/objects.yml` | `make generate-jwk` |
| Add new algorithm | `jwa/objects.yml` | `make generate-jwa` |
| Modify token fields | `jwt/objects.yml` | `make generate-jwt` |

## File Naming Conventions

| Pattern | Meaning |
|---------|---------|
| `*_gen.go` | Generated code - DO NOT EDIT |
| `*_test.go` | Test files |
| `*_gen_test.go` | Generated tests - DO NOT EDIT |
| `options.yaml` | Option definitions (input to genoptions) |
| `objects.yml` | Object definitions (input to package-specific generators) |

## Examples

Examples live in [`github.com/jwx-go/examples`](https://github.com/jwx-go/examples) (locally at `./examples/` when checked out).

Naming convention: `{package}_xxx_example_test.go`
- `jwt_parse_example_test.go`
- `jws_sign_example_test.go`
- `jwx_example_test.go` (cross-package)
- `jwx_readme_example_test.go` (cross-package, used in README)

Examples are included in `docs/` via autodoc markers (resolved by `scripts/autodoc.pl`):
```markdown
<!-- INCLUDE(examples/jwt_parse_example_test.go) -->
<!-- END INCLUDE -->
```

## Pre-Read Rules

Read linked doc BEFORE working in that area. No exceptions.

| Trigger | Doc |
|---------|-----|
| Looking up package APIs, types, functions | `agents/docs/packages.md` |
| Running or writing tests, fuzz tests | `agents/docs/testing.md` |
| Understanding package relationships, imports | `agents/docs/dependencies.md` |
| Working with errors, error handling patterns | `agents/docs/error-formatting.md` |
| Code generation, options pattern, extension points, JSON/base64 backends | `agents/docs/internals.md` |
| Extension modules (ES256K, Ed448, ML-DSA, ML-KEM, X448, compsig, asmbase64, jwkcache) | `docs/10-extensions.md` |
| Companion modules, CI templates, `/jwx-companion-bulk` | `agents/docs/companions.md` |
| Reverse-syncing action versions from companion workflows into templates | `agents/docs/companion-template-sync.md` |
| Cutting a release / tagging a new version | `agents/docs/release.md` |

## Cache Maintenance

These docs cache repository state. Still read source before modifying code.

1. When your changes affect a doc below, update it in the same commit.
2. If you notice any doc is wrong or stale — even on an unrelated task — fix it immediately.

| Doc | Update trigger |
|-----|----------------|
| `agents/docs/packages.md` | New/renamed/removed exported functions, types, or packages |
| `agents/docs/testing.md` | Changes to test infrastructure, build tags, test helpers, fuzz targets |
| `agents/docs/dependencies.md` | New internal imports between packages, new external dependencies |
| `agents/docs/error-formatting.md` | New sentinel errors, changes to error wrapping patterns |
| `agents/docs/internals.md` | Changes to generators, options YAML schema, registration points, multi-module layout |
| `agents/docs/companions.md` | Changes to companion module tooling, templates, `companions.yaml`, or `.companions/` layout |
