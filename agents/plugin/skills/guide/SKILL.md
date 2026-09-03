---
name: jwx-guide-v4
description: Guide for developing Go applications with github.com/lestrrat-go/jwx v4 — parse/sign JWTs, work with JWS/JWE/JWK, pick algorithms, and avoid the common footguns. For developers using jwx, not for developing the library itself.
---

# jwx-guide-v4

This skill helps you assist Go developers who are **using** `github.com/lestrrat-go/jwx/v4` in their own projects. It is scoped to **v4** only — for v3 or v2, install the corresponding `jwx-dev-v3` / `jwx-dev-v2` plugin.

## Where to look things up

You will not have this repository checked out. To verify an API claim before answering, use these sources, in order of preference:

1. **Go module cache** — if the user's project depends on jwx, the source is on disk:
   ```bash
   echo "$(go env GOMODCACHE)/github.com/lestrrat-go/jwx/v4@$(go list -m -f '{{.Version}}' github.com/lestrrat-go/jwx/v4)"
   ```
   This directory contains the full source tree including `docs/`, `jwt/`, `jws/`, `jwe/`, `jwk/`, `jwa/`.
2. **pkg.go.dev** — canonical API reference for any exported symbol:
   - `https://pkg.go.dev/github.com/lestrrat-go/jwx/v4`
   - `https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt` (etc. per subpackage)
3. **GitHub** — narrative documentation lives at the repo:
   - `https://github.com/lestrrat-go/jwx/blob/develop/v4/docs/01-jwt.md`
   - `https://github.com/lestrrat-go/jwx/blob/develop/v4/docs/02-jws.md`
   - `https://github.com/lestrrat-go/jwx/blob/develop/v4/docs/03-jwe.md`
   - `https://github.com/lestrrat-go/jwx/blob/develop/v4/docs/04-jwk.md`
   - `https://github.com/lestrrat-go/jwx/blob/develop/v4/docs/10-extensions.md`
   - `https://github.com/lestrrat-go/jwx/blob/develop/v4/docs/99-faq.md`
4. **Examples repo** — runnable usage patterns. The repo's `README.md` is a topical index that maps "what do I want to do" → "which `*_example_test.go` file." Fetch the README first when looking for an example by topic; then fetch the linked file:
   - `https://github.com/jwx-go/examples/blob/develop/v4/README.md`

When the user's question goes beyond the patterns in this skill (custom claim types, JWE recipients with per-recipient headers, nested JWS+JWE serializers, custom key providers, base64 backend swap, performance tuning), fetch from these sources rather than guessing.

## Prerequisites

- **Go 1.26+** is required. v4 uses generics features and stdlib additions (`errors.AsType[T]`) that are new in 1.26.
- **`GOEXPERIMENT=jsonv2`** must be set on Go 1.26 for every `go build`/`go test`/`go run`, because v4 depends on `encoding/json/v2`. Without it → builds fail with `build constraints exclude all Go files`. NEVER set it on Go 1.27+ → `encoding/json/v2` is in the standard library there, and naming the experiment rebuilds the standard library under a non-default configuration.

Sub-package map:

| Package | Role |
|---------|------|
| `jwa` | Algorithm identifiers as **functions**: `jwa.RS256()`, `jwa.ES256()`, `jwa.HS256()`, `jwa.A256GCM()`, `jwa.RSA_OAEP_256()`, `jwa.EdDSA()`, etc. |
| `jwk` | JSON Web Keys: parsing, generating, import/export between `jwk.Key` and `crypto.*` keys, key sets. |
| `jws` | Sign and verify arbitrary payloads (compact or JSON serialization). |
| `jwe` | Encrypt and decrypt arbitrary payloads. |
| `jwt` | JWT tokens — claims, signing, verification + validation. Wraps `jws`. |
| `jwt/openid` | OpenID Connect ID-token-flavored claims. |

## Critical rules (read first)

1. **`jwt.Parse` verifies AND validates by default.** A bare `jwt.Parse(data)` errors because no key was supplied. To intentionally skip both, use `jwt.ParseInsecure`. To verify but skip claim validation, pass `jwt.WithValidate(false)`. This is deliberately asymmetric vs. `jws.Parse`/`jwe.Parse` (which only parse). Do not "correct" it.
2. **Always pin the algorithm on the verify side.** `jwt.WithKey(jwa.RS256(), key)`, `jws.WithKey(jwa.ES256(), key)`. Never trust the `alg` from the incoming header alone.
3. **Never use `jwt.ParseInsecure` for tokens received from the network.** It is for testing or for extracting claims from a token whose origin is already trusted by other means.
4. **`jwa` algorithms are functions in v4, not constants.** Write `jwa.RS256()`, not `jwa.RS256`. This trips up users migrating from v2/v3.
5. **`kid` matching is enforced when verifying with a JWK Set.** Override the requirement with `jwt.WithKeySet(set, jws.WithRequireKid(false))` only when you understand the consequences.
6. **`jku` (key URL in the JWS header) is attacker-controlled.** Use `jwt.WithVerifyAuto` only with a `jwkfetch.Client` configured with a `jwkfetch.NewMapWhitelist()` of allowed URLs.
7. **HMAC keys are `[]byte`, not `string`.** Pass `[]byte("secret")`, or better, a `jwk.Key` imported from those bytes.
8. **Generic functions require explicit type parameters.** `jwk.ParseKey[jwk.Key](data)`, `jwk.Import[jwk.Key](raw)`, `jwk.Export[*rsa.PublicKey](key)`. Bare `jwk.ParseKey(data)` does **not** compile.

## Verifying a JWT (the 90% case)

```go
import (
    "github.com/lestrrat-go/jwx/v4/jwa"
    "github.com/lestrrat-go/jwx/v4/jwt"
)

tok, err := jwt.Parse(raw, jwt.WithKey(jwa.RS256(), publicKey))
if err != nil {
    // signature failed, claim validation failed, or parse failed
    return err
}
// tok is verified + validated; safe to read claims
```

`publicKey` may be:
- a `*rsa.PublicKey` / `*ecdsa.PublicKey` / `ed25519.PublicKey` from `crypto/*`
- `[]byte` for HMAC algorithms
- a `jwk.Key`

To validate against expected claim values, pass `jwt.WithIssuer(...)`, `jwt.WithAudience(...)`, `jwt.WithSubject(...)`, `jwt.WithJwtID(...)`. To extend the default clock skew window: `jwt.WithAcceptableSkew(30 * time.Second)`.

### Verifying with a JWK Set (kid-based key selection)

```go
set, err := jwk.Parse(jwksBytes)
if err != nil { return err }

tok, err := jwt.Parse(raw, jwt.WithKeySet(set))
```

If the JWS header has a `kid`, the matching key is selected from the set. The algorithm comes from each key's `alg` field. To opt out of kid-required matching: `jwt.WithKeySet(set, jws.WithRequireKid(false))`.

**A key with no `alg` field is skipped, not guessed at.** Inference from the key type is opt-in via `jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true))`, and it is a fallback, not a default. It tries every algorithm compatible with the key type, so it is slower and weaker than an explicit `alg`; combined with `jws.WithRequireKid(false)` against a large JWKS it also multiplies out to `N_keys × N_algs_per_keytype` verification attempts. The right fix is almost always to add `alg` to the keys in the JWKS. If a user reports that verification against a JWKS silently finds no usable key, check for missing `alg` fields first.

### Verifying via JWKS endpoint

HTTP fetching is **not** in the core `jwk` package in v4. It lives in a companion module:

```go
import "github.com/jwx-go/jwkfetch/v4"

client := jwkfetch.NewClient()
set, err := client.Fetch(ctx, "https://issuer.example/jwks.json")
// then: jwt.Parse(raw, jwt.WithKeySet(set))
```

For repeated fetches with background refresh, use `jwkfetch.NewCache`. For `jku`-driven verification, build a `jwkfetch.Client` with a `jwkfetch.NewMapWhitelist()` of allowed URLs and pass it to `jwt.WithVerifyAuto(client)`.

## Signing a JWT

```go
tok, err := jwt.NewBuilder().
    Issuer("https://issuer.example").
    Audience([]string{"https://api.example"}).
    Subject("user-123").
    IssuedAt(time.Now()).
    Expiration(time.Now().Add(15 * time.Minute)).
    Claim("scope", "read:things").
    Build()
if err != nil { return err }

signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privateKey))
```

`privateKey` may be a `*rsa.PrivateKey`/`*ecdsa.PrivateKey`/`ed25519.PrivateKey`/HMAC `[]byte`, or a `jwk.Key`.

Match algorithm to key type:

| Family | Use when |
|--------|----------|
| `HS256` / `HS384` / `HS512` | Shared-secret (HMAC). Same secret signs and verifies. |
| `RS256` / `RS384` / `RS512` | RSA, widest interop. |
| `PS256` / `PS384` / `PS512` | RSA-PSS, prefer over `RS*` for new systems. |
| `ES256` / `ES384` / `ES512` | ECDSA, smaller signatures than RSA. |
| `EdDSA` | Ed25519, fastest verify; preferred for new systems where supported. |
| `none` | **Never.** jwx refuses by default. |

## JWK basics

All generic accessors require the type parameter:

```go
// Parse a single JWK (returns jwk.Key):
key, err := jwk.ParseKey[jwk.Key](jwkBytes)

// Parse a single JWK with a concrete type (fails if not that type):
rsaKey, err := jwk.ParseKey[jwk.RSAPublicKey](jwkBytes)

// Parse a JWK Set (returns jwk.Set, not generic):
set, err := jwk.Parse(jwksBytes)

// Wrap an existing crypto.* key as a jwk.Key:
key, err := jwk.Import[jwk.Key](rsaPrivKey)

// Or with a concrete jwk type:
typed, err := jwk.Import[jwk.RSAPrivateKey](rsaPrivKey)

// Export a jwk.Key back to a crypto.* key:
raw, err := jwk.Export[*rsa.PublicKey](key)
```

`jwk.Import[jwk.Key]` is the default. Use a concrete type parameter (`jwk.RSAPrivateKey`, `jwk.ECDSAPublicKey`, `jwk.SymmetricKey`, `jwk.OKPPublicKey`, etc.) only when you want compile-time guarantees and acceptance of failure when the input is anything else.

### Generating keys

```go
import (
    "crypto/rand"
    "crypto/rsa"

    "github.com/lestrrat-go/jwx/v4/jwa"
    "github.com/lestrrat-go/jwx/v4/jwk"
)

raw, _ := rsa.GenerateKey(rand.Reader, 2048)
key, _ := jwk.Import[jwk.Key](raw)
key.Set(jwk.KeyIDKey, "2025-q1")
key.Set(jwk.AlgorithmKey, jwa.RS256())

pubKey, _ := jwk.PublicKeyOf(key)
```

`jwk.KeyIDKey` and `jwk.AlgorithmKey` are string constants for the standard JWK fields `kid` and `alg`.

## JWS (signing arbitrary payloads)

```go
sig, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), privateKey))
payload, err := jws.Verify(sig, jws.WithKey(jwa.ES256(), publicKey))
```

`jws.Parse` only parses the structure — it does **not** verify. Use `jws.Verify` (which returns the verified payload) for verification.

## JWE (encrypting payloads)

```go
enc, err := jwe.Encrypt(
    payload,
    jwe.WithKey(jwa.RSA_OAEP_256(), recipientPublicKey),
    jwe.WithContentEncryption(jwa.A256GCM()),
)

plain, err := jwe.Decrypt(enc, jwe.WithKey(jwa.RSA_OAEP_256(), recipientPrivateKey))
```

`jwe.WithKey(alg, key)` is the same on both encrypt and decrypt sides — this symmetry is intentional.

## Companion modules

Beyond the core `github.com/lestrrat-go/jwx/v4` module, the project ships companion modules under `github.com/jwx-go`. The agent should know **what's available and when to reach for each one** — depth lives in each module's godoc.

For algorithm and HPKE modules: **import for side effects** (`import _ "..."`). They register themselves in `init()` and panic at import time if registration fails (intentional — surfaces problems early).

### Signature algorithms (extension)

| Module | What it enables | When to use |
|--------|-----------------|-------------|
| `github.com/jwx-go/mldsa/v4` | ML-DSA-44/65/87 (FIPS 204 post-quantum) | Forward-looking post-quantum signing. AKP key type, `"alg"` field required on keys. |
| `github.com/jwx-go/ed448/v4` | EdDSA (Ed448 curve) | When Ed25519 isn't strong enough or interop requires Ed448. |
| `github.com/jwx-go/es256k/v4` | ES256K (secp256k1) | Web3/crypto ecosystem interop. Uses ECDSA with the secp256k1 curve. |
| `github.com/jwx-go/compsig/v4` | ML-DSA composite signatures (PQ + classical) per draft-ietf-jose-pq-composite-sigs | **Experimental, draft-spec.** Hybrid signing during PQ transition. |

### Key agreement / encryption (extension)

| Module | What it enables | When to use |
|--------|-----------------|-------------|
| `github.com/jwx-go/x448/v4` | X448 ECDH-ES, HPKE with DHKEM(X448), incl. HPKE-5-KE and HPKE-6-KE | Stronger ECDH than X25519 when required. |
| `github.com/jwx-go/mlkem/v4` | ML-KEM-768/1024 (post-quantum KEM) per draft-ietf-jose-pqc-kem | **Experimental, draft-spec.** Post-quantum key encapsulation. |
| `github.com/jwx-go/reddy-pqchpke/v4` | Hybrid PQ HPKE per draft-reddy-cose-jose-pqc-hybrid-hpke | **Highly experimental, pre-WG-adoption.** PQ + classical hybrid. |

### Tooling and backends

| Module | What it does | When to use |
|--------|--------------|-------------|
| `github.com/jwx-go/jwkfetch/v4` | HTTP JWK Set retrieval — `Client` (one-shot) and `Cache` (background-refreshed, backed by `httprc`) | **Always**, whenever you fetch JWKS over HTTP. Core jwx has no HTTP dependency; this is the entry point. |
| `github.com/jwx-go/asmbase64/v4` | Assembly-optimized base64 backend (via `segmentio/asm`) | High-throughput JWS verify/decode paths where base64 is hot. Drop-in import. |
| `github.com/jwx-go/jwxmigrate` | Machine-readable v3→v4 migration rules and automated checking | A user porting an app from jwx/v3 to jwx/v4. |
| `github.com/jwx-go/examples` | Runnable usage patterns covering JWT/JWS/JWE/JWK/extensions; `README.md` is a topical index by package and sub-topic | Pointing the user at canonical example code — fetch the README first to find the right file by topic, then fetch the linked test file. Also importable via `go.work` in local development. |

### Cross-references

- Canonical extension docs (always-current list, with examples): `https://github.com/lestrrat-go/jwx/blob/develop/v4/docs/10-extensions.md`
- Each companion's godoc: `https://pkg.go.dev/github.com/jwx-go/<name>/v4`

### What to do when the user asks about post-quantum or non-default algorithms

Default jwx supports the common RFC 7518 algorithms (RS*, PS*, ES*, HS*, EdDSA, A*GCM, RSA-OAEP-*, etc.) out of the box. For everything in the tables above, the user must add the companion module to their `go.mod` *and* import it for side effects. If a user reports an `algorithm not registered` or similar error for ES256K/Ed448/ML-DSA/ML-KEM/X448, they almost certainly missed the side-effect import.

ML-DSA is the one exception, and it depends on the toolchain. From Go 1.27 on, `crypto/mldsa` is in the standard library, so jwx registers `jwa.MLDSA44()`/`MLDSA65()`/`MLDSA87()` natively and no companion module or side-effect import is needed. On Go 1.26 the algorithms are not registered at all, and `github.com/jwx-go/mldsa/v4` is still required. Canonical owner: `docs/10-extensions.md`, section "Which implementation you get".

## Errors

JWT/JWS/JWE/JWK errors are struct types with named fields. Use `errors.Is` with a zero-value struct to test for *kind*, or Go 1.26's `errors.AsType[T]` to recover the *fields*:

```go
import "errors"

tok, err := jwt.Parse(raw, jwt.WithKey(jwa.RS256(), key))
if err != nil {
    if errors.Is(err, jwt.TokenExpiredError{}) {
        // exp claim failed
    }
    if e, ok := errors.AsType[jwt.InvalidAudienceError](err); ok {
        log.Printf("audience mismatch: %+v", e)
    }
}
```

Common types:
- `jwt`: `TokenExpiredError`, `TokenNotYetValidError`, `InvalidIssuerError`, `InvalidAudienceError`, `MissingRequiredClaimError`, `ValidationError`, `ParseError`
- `jws`: `VerificationError()` factory (signature verification failed)
- `jwe`: `DecryptError()` factory, `AlgorithmMismatchError`
- `jwk`: `KeyTypeMismatchError`, `ImportError()`, `ParseError()`

Do not match errors by string contents — messages may change.

## Token field access

Standard claims have dedicated typed accessors (returning `(value, ok)`):

```go
exp, ok := tok.Expiration()  // time.Time
iss, ok := tok.Issuer()      // string
aud, ok := tok.Audience()    // []string
sub, ok := tok.Subject()     // string
nbf, ok := tok.NotBefore()
iat, ok := tok.IssuedAt()
jti, ok := tok.JwtID()
```

For private claims, use `tok.Field(name)` which returns `(any, bool)`. For type-safe access, use `jwt.Get[T](tok, name)`.

## Common mistakes to flag in user code

When reviewing or writing jwx-using code, watch for these:

1. `jwt.Parse(data)` with no key option — errors out; if the intent was to read claims without verifying, that's a security bug unless the source is already trusted, in which case use `jwt.ParseInsecure`.
2. `jwa.RS256` instead of `jwa.RS256()` — these are functions in v4.
3. `jwk.ParseKey(data)` or `jwk.Import(raw)` without the type parameter — won't compile.
4. Type-asserting a `jwk.Key` to a `crypto.*` type. Use `jwk.Export[*rsa.PublicKey](key)` instead.
5. Hardcoding the alg from the JWS header (or token contents) to pick a verifier — always pin the expected algorithm on the verify side.
6. Reusing a single `jwt.Builder` across goroutines — builders aren't safe to share.
7. Verifying by passing a *private* key — works but leaks intent. Use the public key on the verify side.
8. Manually building JWS compact strings via concatenation — always go through `jws.Sign`/`jwt.Sign`.
9. `tok.Get("exp")` — the method is `tok.Field("exp")` (or just `tok.Expiration()`).
10. Disabling kid matching as a "make it work" shortcut. Understand why the kid doesn't match before adding `jws.WithRequireKid(false)`.

## What NOT to suggest

- Disabling signature verification to "make it work."
- Forking or vendoring jwx to add an algorithm — recommend the extension modules listed above.
- Decoding the JWT envelope with `encoding/json` directly — always go through `jwt.Parse` / `jws.Verify`.
- Recommending a different JWT library — out of scope for this skill.
