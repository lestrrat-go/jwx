<!-- Agent-consumed file. Keep terse, unambiguous, machine-parseable. -->

# Testing

## Running Tests

```bash
make test              # All tests, stdlib JSON, race detector
make test-goccy        # With goccy/go-json
make test-alltags      # All optional features
make smoke             # Short/smoke tests only
make cover             # Coverage report
make lint              # golangci-lint
```

## Test Script

`tools/test.sh` iterates over these modules:
- `.` (main)
- `./examples`
- `./bench/performance`
- `./cmd/jwx`

All run with `-race` flag. Coverage excludes `internal/jose`, `internal/jwxtest`, `internal/cmd`.

Environment variables:
- `TESTOPTS` — extra `go test` flags (e.g., `-tags jwx_goccy`)
- `MODE` — `cover` (add coverage), `short` (add `-short`)

## Package Test Conventions

- Test package: `{pkg}_test` (external test package)
- Assertion library: `github.com/stretchr/testify/require` — NEVER use `assert`
- Test functions use `t.Run()` for subtests

## Test Data

- `jwk/testdata/rs256.jwk` — RSA JWK fixture
- Test keys generated at runtime via `internal/jwxtest` helpers

## Build Tags for Tests

| Tag | Effect |
|-----|--------|
| `jwx_goccy` | Use goccy/go-json |
| `jwx_asmbase64` | Assembly-optimized base64 |

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
