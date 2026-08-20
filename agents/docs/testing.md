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

The only build tags in the tree are Go-version constraints, and tests never set
them; the toolchain selects the files. Two groups exist: the json/v2 sentinel
shim (`internal/json/skipfunc_pre_go127.go` / `skipfunc_go127.go`), and native
ML-DSA (`jwa/signature_go127_gen.go`, `jwk/mldsa.go`, `jws/mldsa.go` plus their
tests, all `//go:build go1.27`).

ML-DSA coverage therefore runs only on Go 1.27: `jwa/mldsa_test.go`,
`jwa/signature_go127_gen_test.go` (generated; DO NOT EDIT),
`jwk/mldsa_test.go` (import/export, JWK round-trip, thumbprint, and known-answer
vectors pinned from a fixed seed), `jws/mldsa_test.go` (sign/verify, parameter-set
confusion, signer-opts handling), and `jws/mldsa_fuzz_test.go`. On Go 1.26 these
files do not compile in, so the suite is silently smaller — check the toolchain
before concluding ML-DSA is untested.

## Go 1.27

Both Go 1.26 and Go 1.27 build and pass from the same source. Go 1.26 needs
`GOEXPERIMENT=jsonv2`; Go 1.27 ships `encoding/json/v2` in the standard library
and must NOT set it. The Makefile probes the toolchain and rewrites
`GOEXPERIMENT` to match, adding `jsonv2` on Go 1.26 and stripping it on Go 1.27,
so `make` handles this either way even when the variable is already exported.
Go 1.27 does still require `-vet=off`:

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

Each of those two jobs also asserts the experiment its toolchain expects, via
`make print-goexperiment`. `Test` requires `jsonv2` and `Test (Go 1.27)`
requires the empty string, so a broken probe cannot quietly flip either one.
When `go.mod` moves to 1.27, the `Test` job's expectation becomes the empty
string and `Test (Go 1.27)` goes away with the rest of the shim.

## Fuzz Tests

```bash
make fuzz              # All fuzz targets (default 30s each)
make fuzz-jwt          # FuzzParse, FuzzSignAndParse
make fuzz-jws          # FuzzParse, FuzzSignAndVerify
make fuzz-jwe          # FuzzParse, FuzzEncryptAndDecrypt
make fuzz-jwk          # FuzzParseKey, FuzzParse, FuzzParseKeyRoundtrip
FUZZTIME=5m make fuzz  # Override fuzz duration
```

`jws/mldsa_fuzz_test.go` adds `FuzzMLDSASignAndVerify` and
`FuzzMLDSAJWKRoundTrip`. Neither is wired into `make fuzz-jws`, because both are
`//go:build go1.27` and naming a missing target would break `make fuzz` on Go
1.26. Run them directly on a Go 1.27 toolchain:

```bash
go test ./jws/ -run "^$" -fuzz FuzzMLDSASignAndVerify -fuzztime 30s
```

Their `f.Add` seeds still execute during a normal `go test` run on Go 1.27, so
the seed corpus is covered by `make test` there. Wire both into `make fuzz-jws`
once `go.mod` moves to 1.27.

## Test Helpers (internal/jwxtest)

Key generation helpers for tests:
- RSA, ECDSA, Ed25519, symmetric key generation
- JWT/JWS/JWE/JWK operation helpers
