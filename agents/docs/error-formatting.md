<!-- Agent-consumed file. Keep terse, unambiguous, machine-parseable. -->

# Error Handling

## Pattern

Error types are defined directly in their respective packages.
Use `errors.Is()` with a zero-value struct for type checks, and `errors.AsType[T]()` to
extract structured fields:

```go
// Type check (zero-value matching)
if errors.Is(err, jwt.TokenExpiredError{}) { ... }

// Extract structured detail
if expErr, ok := errors.AsType[jwt.TokenExpiredError](err); ok {
    log.Printf("expired at %s, checked at %s", expErr.Expiration, expErr.Now)
}
```

Only `jwt.UnknownPayloadTypeError()` remains a sentinel function (no struct type).

## Exported Error Types (jwt)

| Type | Structured Fields | Meaning |
|------|------------------|---------|
| `TokenExpiredError` | `Expiration`, `Now`, `Skew` | `exp` claim not satisfied |
| `TokenNotYetValidError` | `NotBefore`, `Now`, `Skew` | `nbf` claim not satisfied |
| `InvalidIssuedAtError` | `IssuedAt`, `Now`, `Skew` | `iat` claim not satisfied |
| `InvalidIssuerError` | *(none)* | `iss` claim not satisfied |
| `InvalidAudienceError` | *(none)* | `aud` claim not satisfied |
| `ClaimValidationError` | `Claim`, `Expected`, `Actual` | Generic claim validator mismatch |
| `TimeDeltaError` | `Claim1`, `Claim2`, `Value1`, `Value2`, `Delta`, `Limit`, `Skew` | Time delta out of range |
| `ValidationError` | *(wraps inner)* | Blanket validation failure |
| `ParseError` | *(wraps inner)* | Parse failed |
| `MissingRequiredClaimError` | `Claim` | Required claim missing |
| `ClaimNotFoundError` | `Name` | Claim not present (`jwt.Get` miss) |
| `ClaimTypeMismatchError` | `Name`, `Got`, `Want` | Claim present but wrong type (`jwt.Get` type assertion failed) |
| `ClaimAssignmentFailedError` | `Err` | Claim value assignment failed |

## Exported Error Types (jwk)

| Type | Structured Fields | Meaning |
|------|------------------|---------|
| `KeyTypeMismatchError` | `Got`, `Want` (both `reflect.Type`) | Generic type parameter on `Import[T]` / `ParseKeyAs[T]` / `Export[T]` / `ExportAll[T]` does not match the value the function produced |
| `UnknownKeyTypeError` | `KeyType` (string; empty when `kty` was missing) | Probe couldn't resolve `kty` to a known key family. Empty `KeyType` = `kty` field absent or non-string; populated = `kty` was a string but unrecognized |
| `FieldNotFoundError` | `Name` | Field not present (`jwk.Get` miss) |
| `FieldTypeMismatchError` | `Name`, `Got`, `Want` | Field present but wrong type (`jwk.Get` type assertion failed) |

## Exported Error Types (jws)

| Type | Structured Fields | Meaning |
|------|------------------|---------|
| `FieldNotFoundError` | `Name` | Header field not present (`jws.Get` miss) |
| `FieldTypeMismatchError` | `Name`, `Got`, `Want` | Header field present but wrong type (`jws.Get` type assertion failed) |

## Exported Error Types (jwe)

| Type | Structured Fields | Meaning |
|------|------------------|---------|
| `MissingContentEncryptionError` | *(none)* | `enc` missing from protected headers during `Decrypt` |
| `AlgorithmMismatchError` | `Expected`, `Got` (both `jwa.KeyEncryptionAlgorithm`) | Per-recipient/protected `alg` does not match the key's algorithm |
| `FieldNotFoundError` | `Name` | Header field not present (`jwe.Get` miss) |
| `FieldTypeMismatchError` | `Name`, `Got`, `Want` | Header field present but wrong type (`jwe.Get` type assertion failed) |

## Sentinel Function Registry

| Package | Function | Meaning |
|---------|----------|---------|
| `jwt` | `UnknownPayloadTypeError()` | Unrecognized payload format |
| `jws` | `SignError()` | Signing failed |
| `jws` | `VerifyError()` | Verification process error |
| `jws` | `VerificationError()` | Signature mismatch |
| `jws` | `ParseError()` | Parse failed |
| `jws` | `ErrCritPresent()` | `VerifyCompactFast` refused a `crit`-bearing protected header (use `jws.Verify`) |
| `jws` | `ErrB64Present()` | `VerifyCompactFast` refused a `b64`-bearing protected header (use `jws.Verify`) |
| `jws` | `ErrNonMinimalHeader()` | `VerifyCompactFast` refused a protected header outside the fast-path minimal shape — alg×1 + optional single typ/kid/cty, no escapes/duplicates/extras (use `jws.Verify`) |
| `jws` | `ErrUnclassifiableKey()` | Key classification failed at option time in `Sign`/`Verify` (Import failed, kty not registered, or key-agreement-only key like ecdh). Sentinel defined in `jws/internal/keyalg`; `jws.ErrUnclassifiableKey()` re-exports it |
| `jwe` | `EncryptError()` | Encryption failed |
| `jwe` | `DecryptError()` | Decryption failed |
| `jwe` | `HPKEError()` | HPKE encrypt/decrypt operation failed |
| `jwe` | `RecipientError()` | Recipient processing error |
| `jwe` | `ParseError()` | Parse failed |
| `jwk` | `ImportError()` | Key import failed |
| `jwk` | `ParseError()` | Key parse failed |
| `jwk` | `WhitelistError()` | URL not whitelisted |
| `jwk` | `ContinueError()` | Skip key (used by parsers) |
| `jwa` | `ErrInvalidKeyAlgorithm()` | Invalid algorithm |

## Error Helpers

- `jwk.IsKeyValidationError(err error) bool` — returns `true` if `err` indicates a key validation failure.

## Collect-All Validation Errors

By default, `jwt.Validate()` returns on first failure (v3 behavior).
Use `jwt.WithCollectErrors(true)` to gather all validation errors:

```go
err := jwt.Validate(token, jwt.WithIssuer("x"), jwt.WithCollectErrors(true))
// err wraps all failures via errors.Join; each cause is reachable via errors.Is / errors.AsType
```

## Error Wrapping

Errors wrap typed errors with `fmt.Errorf("context: %w", inner)`. Chain checking works:

```go
// Both match:
errors.Is(err, jwt.ValidationError{})    // outer
errors.Is(err, jwt.TokenExpiredError{})   // inner (wrapped by ValidationError)
```

## Rules

- NEVER compare errors with `==`. ALWAYS use `errors.Is()` or `errors.AsType[T]()`.
- For jwt error types, use zero-value struct for `errors.Is` checks: `jwt.TokenExpiredError{}`.
- Error types are defined directly in the `jwt` package (not in `jwt/internal/errors`).
- Constructor helpers (`parseErrorf`, `validateErrorf`, etc.) are unexported functions in the `jwt` package.
