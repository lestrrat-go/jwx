# JWE Encrypt/Decrypt Refactoring Investigation

## Context

The jwe package has grown organically as new algorithm families (most recently ML-KEM) were added. Each new algorithm requires coordinated changes across 5-6 files: `encrypt.go`, `decrypt.go`, `jwe.go` (decryptContent), `jwebb/key_encryption.go`, `keygen/interface.go`, and sometimes `headers.go`. This document identifies concrete refactoring opportunities to improve maintainability, reduce scatter, and fix latent bugs.

---

## Findings by Category

### 1. Bugs / Dead Code (Fix Immediately)

| # | Issue | File | Details |
|---|-------|------|---------|
| 1a | **`isZero()` missing `encapsulatedKey`** | `jwe/headers.go:14-31` | Hand-written `isZero()` does not check `encapsulatedKey`, but generated `clear()` in `headers_gen.go` does nil it. This means `isZero()` returns `true` for headers that still have an `ek` value set. Affects ML-KEM serialization paths where `isZero` gates header inclusion (message.go:267, 440). |
| 1b | **Dead `cipher` field on `encrypter`** | `jwe/encrypt.go:27` | `encrypter.cipher` is set in `newEncrypter` via `jwebb.CreateContentCipher` but never read -- `EncryptKey()` doesn't reference `e.cipher`. Dead allocation + dead code. |
| 1c | **Unused `*content_crypt.Generic` param** | `jwe/jwe.go:84` | `recipientBuilder.Build()` takes `_ *content_crypt.Generic` that is never used. |
| 1d | **`%s` instead of `%w` for lastError** | `jwe/jwe.go:398` | `tryRecipient` stringifies `lastError` with `%s`, losing the error chain. Should be `%w` for proper `errors.Is`/`errors.As` support. |

### 2. Algorithm Dispatch (Structural)

**Current:** `EncryptKey()` (encrypt.go, 209 lines) and `DecryptKey()` (decrypt.go, 248 lines) are linear if/else chains dispatching on `jwebb.IsXxx(algStr)`. `decryptContent()` (jwe.go:401-559, 158 lines) has a parallel switch for algorithm-specific header extraction.

**Opportunity: Registry-based dispatch (following JWS pattern)**

Define a `KeyAlgorithmHandler` interface that encapsulates encrypt-key, decrypt-key, and header extraction:

```go
type KeyAlgorithmHandler interface {
    EncryptKey(ctx KeyEncryptParams) (KeyEncryptResult, error)
    PrepareDecrypter(headers Headers, dec *decrypter) error
    DecryptKey(ctx KeyDecryptParams) ([]byte, error)
}
```

Register per-algorithm-family handlers in a `map[jwa.KeyEncryptionAlgorithm]KeyAlgorithmHandler`. The if/else chains in encrypt.go/decrypt.go and the switch in decryptContent become simple map lookups + handler calls.

**Trade-offs:**
- (+) Adding a new algorithm = implement interface + register. No scatter across 3 files.
- (+) Consistent with JWS Signer/Verifier registry pattern already in the codebase.
- (+) Each handler is self-contained and independently testable.
- (-) `KeyEncryptParams`/`KeyDecryptParams` become parameter bags (but the current `encrypter`/`decrypter` structs already are).
- (-) Significant refactoring effort; touches security-critical paths.

**Alternative: Thin dispatch table (lighter touch)**

Extract each if/else branch body into a named function. Use `map[string]func(...)` for dispatch. Keeps current struct shapes, just organizes the dispatch.

- (+) Minimal architectural change.
- (-) Still requires 3 separate maps (encrypt, decrypt, header extraction).

### 3. Internal Struct Design

**3a. `decrypter` god-struct** (decrypt.go:16-34)

17 fields, most only used by specific algorithm families. The builder pattern (`.KeySalt()`, `.EncapsulatedKey()`, etc.) allows setting fields that don't apply to the current algorithm.

**Opportunity:** Per-family constructor functions (`newPBES2Decrypter(headers, key, ...)`, `newECDHESDecrypter(headers, key, ...)`) that each extract their own headers and validate parameters internally. The `decryptContent` switch becomes a thin dispatcher that delegates to the right constructor.

**3b. `encrypter` pubkey/rawKey confusion** (encrypt.go:20-28)

`pubkey` serves dual purpose: "original key for `KeyEncrypter` interface check" and "fallback if rawKey is nil." The `keyToUse = e.rawKey; if keyToUse == nil { keyToUse = e.pubkey }` pattern repeats 4 times (ECDH-ES, ML-KEM, RSA1_5, RSA-OAEP).

**Opportunity:** Resolve the key fully at construction time. Store `customEncrypter KeyEncrypter` (if applicable) separately. Eliminate nil-fallback pattern with a `resolveKey(rawKey, pubkey)` helper.

**3c. ByteSource hierarchy** (keygen package)

5 types (`ByteKey`, `ByteWithECPublicKey`, `ByteWithIVAndTag`, `ByteWithSaltAndCount`, `ByteWithEncapsulatedKey`) each implementing `populater` to write metadata into headers. Adding a new algorithm = new type + new Populate impl.

**Opportunity:** Replace with flat `KeyEncryptResult`:
```go
type KeyEncryptResult struct {
    Key          []byte
    IsDirect     bool
    HeaderParams []HeaderParam // [{Name: "epk", Value: jwkKey}, ...]
}
```
Eliminates type hierarchy, makes header population generic. Each `jwebb.KeyEncrypt*` returns this directly.

### 4. Error Handling

- **Inconsistent prefixes**: encrypt.go mixes `"encrypt key: "`, `"encrypt: "`, `"failed to "`, and bare messages. decrypt.go same.
- **Structured RecipientError**: current `recipientError` is a thin wrapper. Could carry recipient index + algorithm for multi-recipient debugging.

### 5. Pool Safety

- `isZero()` drift (see 1a) is a systemic risk: hand-written functions get out of sync with generated field lists.
- **Opportunity:** Generate `isZero()` alongside `clear()` in the header generator, ensuring both cover the same fields.
- **Opportunity:** Pool safety test -- alloc, set all fields, return, re-get, assert zero.
- **Question:** Are `encryptContext`/`decryptContext` pools worth the reset-safety burden? Crypto ops dominate cost. Worth benchmarking.

### 6. Serialization

`EncryptMessage` merges per-recipient headers into protected for compact format (jwe.go:791). Then `Compact()` (message.go:505-516) re-merges protected + unprotected + recipient headers. Double merge is wasteful and confusing.

**Opportunity:** Make `Compact()` the single authority for header merging (it already must handle arbitrary Messages), and skip the pre-merge in `EncryptMessage` for compact format.

### 7. Code Duplication

- `keyToUse = e.rawKey; if nil { = e.pubkey }` -- 4 times in encrypt.go. Extract `resolveKey` helper.
- `sharedkey, ok := e.rawKey.([]byte); if !ok { return error }` -- 4 times in encrypt.go, 4 in decrypt.go. Extract `requireByteKey(key, alg)` helper.

---

## Prioritized Action Items

| Priority | Item | Effort | Impact | Notes |
|----------|------|--------|--------|-------|
| P0 | Fix `isZero()` missing `encapsulatedKey` | Trivial | Correctness bug | Add `h.encapsulatedKey == nil &&` |
| P0 | Remove dead `cipher` field from `encrypter` | Trivial | Clarity | Also remove from `newEncrypter` |
| P0 | Remove unused `*content_crypt.Generic` param from `Build()` | Trivial | Clarity | |
| P0 | Fix `%s` to `%w` for lastError in tryRecipient | Trivial | Debuggability | |
| P1 | Generate `isZero()` in header generator | Medium | Prevents future drift | Modify `genheaders` |
| P1 | Extract `resolveKey` + `requireByteKey` helpers | Low | Readability | |
| P1 | Add `jwebb.IsDirectCEK(alg)` predicate | Low | Single update point | Replaces growing alg list in Build() and ProcessOptions() |
| P2 | Per-family decrypter constructors | Medium | Maintainability | Moves header extraction into constructors |
| P2 | Resolve pubkey/rawKey at encrypter construction | Low | Clarity | |
| P2 | Normalize error prefixes | Low | Consistency | v4 major version = safe to change messages |
| P3 | Registry-based algorithm dispatch | High | Extensibility | Follow JWS pattern; biggest win for future algorithms |
| P3 | Replace ByteSource hierarchy with KeyEncryptResult | Medium | Simplicity | Pairs with registry pattern |
| P3 | Fix double header merge in Compact path | Low | Clarity | |
| P4 | Pool safety tests | Low | Regression prevention | |
| P4 | Benchmark pool vs plain alloc for contexts | Low | Data-driven decision | |
