<!-- Agent-consumed file. Keep terse, unambiguous, machine-parseable. -->

# Testing

## Running Tests

```bash
make test              # All tests, race detector
make smoke             # Short/smoke tests only
make cover             # Coverage report
make lint              # golangci-lint
```

## Test Script

`scripts/test.sh` iterates over these modules:
- `.` (main)
- `./cmd/jwx`

All run with `-race` flag. Coverage excludes `internal/jose`, `internal/jwxtest`, `internal/cmd`.

Environment variables:
- `TESTOPTS` — extra `go test` flags (e.g., `-run TestFoo`)
- `MODE` — `cover` (add coverage), `short` (add `-short`)

## Package Test Conventions

- Test package: `{pkg}_test` (external test package)
- Assertion library: `github.com/stretchr/testify/require` — NEVER use `assert`
- Test functions use `t.Run()` for subtests

## Test Data

- `jwk/testdata/rs256.jwk` — RSA JWK fixture
- Test keys generated at runtime via `internal/jwxtest` helpers

## Build Tags for Tests

No feature build tags in v4. Optional features (signature algorithms, base64 backend) are activated via side-effect imports of [extension modules](../docs/10-extensions.md).

The only build tags in the tree are the Go-version constraints on
`internal/json/skipfunc_pre_go127.go` / `skipfunc_go127.go`. Tests never set
them; the toolchain selects the file.

## Go 1.27

Both Go 1.26 (with `GOEXPERIMENT=jsonv2`) and Go 1.27 build and pass from the
same source, but Go 1.27 requires `-vet=off`:

```bash
make test-cmd TESTOPTS=-vet=off   # Go 1.27
```

`go.mod` declares `go 1.26.0`, so under Go 1.27 vet's `stdversion` analyzer
rejects every file that uses `encoding/json/v2` or `jsontext` (`requires go1.27
or later (file is go1.26)`). `go vet ./...` and `make lint` fail on Go 1.27 for
the same reason. Use Go 1.26 for vet and lint until `go.mod` moves to 1.27.

`.github/workflows/ci.yml` covers both: the `Test` job uses the go.mod toolchain
with vet enabled, and `Test (Go 1.27)` runs the same suite with vet disabled.
Every other workflow takes its toolchain from `go.mod`.

## Fuzz Tests

```bash
make fuzz              # All fuzz targets (default 30s each)
make fuzz-jwt          # FuzzParse, FuzzSignAndParse
make fuzz-jws          # FuzzParse, FuzzSignAndVerify
make fuzz-jwe          # FuzzParse, FuzzEncryptAndDecrypt
make fuzz-jwk          # FuzzParseKey, FuzzParse, FuzzParseKeyRoundtrip
FUZZTIME=5m make fuzz  # Override fuzz duration
```

## Test Helpers (internal/jwxtest)

Key generation helpers for tests:
- RSA, ECDSA, Ed25519, symmetric key generation
- JWT/JWS/JWE/JWK operation helpers
