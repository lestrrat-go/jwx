<!-- Agent-consumed file. Keep terse, unambiguous, machine-parseable. -->

# Error Handling

## Pattern

Sentinel errors exposed via functions, not variables. Use `errors.Is()` for checking.

```go
if errors.Is(err, jwt.TokenExpiredError()) { ... }
```

## Sentinel Error Registry

| Package | Function | Meaning |
|---------|----------|---------|
| `jwt` | `TokenExpiredError()` | `exp` claim not satisfied |
| `jwt` | `TokenNotYetValidError()` | `nbf` claim not satisfied |
| `jwt` | `InvalidIssuerError()` | `iss` claim not satisfied |
| `jwt` | `InvalidAudienceError()` | `aud` claim not satisfied |
| `jwt` | `ValidateError()` | Generic validation failure |
| `jwt` | `ParseError()` | Parse failed |
| `jwt` | `ClaimNotFoundError()` | Claim not present |
| `jws` | `SignError()` | Signing failed |
| `jws` | `VerifyError()` | Verification process error |
| `jws` | `VerificationError()` | Signature mismatch |
| `jws` | `ParseError()` | Parse failed |
| `jwe` | `EncryptError()` | Encryption failed |
| `jwe` | `DecryptError()` | Decryption failed |
| `jwe` | `RecipientError()` | Recipient processing error |
| `jwe` | `ParseError()` | Parse failed |
| `jwk` | `ImportError()` | Key import failed |
| `jwk` | `ParseError()` | Key parse failed |
| `jwk` | `WhitelistError()` | URL not whitelisted |
| `jwk` | `ContinueError()` | Skip key (used by parsers) |
| `jwk` | `IsKeyValidationError()` | Key validation failure check |
| `jwa` | `ErrInvalidKeyAlgorithm()` | Invalid algorithm |

## Error Wrapping

Errors wrap sentinels with `fmt.Errorf("context: %w", sentinel)`. Chain checking works:

```go
// Both match:
errors.Is(err, jwt.ValidateError())       // outer
errors.Is(err, jwt.TokenExpiredError())    // inner (wrapped by ValidateError)
```

## Rules

- NEVER compare errors with `==`. ALWAYS use `errors.Is()`.
- Sentinel functions return the same error value each call — safe for `errors.Is()`.
- Custom error types use unexported structs; no type assertions needed.
