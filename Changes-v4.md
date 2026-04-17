# Incompatible Changes from v3 to v4

These are changes that are incompatible with the v3.x.x version.

For a step-by-step migration guide with before/after code examples, see [MIGRATION.md](MIGRATION.md). A machine-readable migration map for AI coding agents and automated tooling is available at [migrate/v3-to-v4.yaml](migrate/v3-to-v4.yaml).

# Detailed list of changes

## Module

* This module now requires Go 1.26

* The number of dependencies in the main module has been trimmed to a bare minimum.
  Features that were previously built into the main module or gated behind build tags
  are now provided by extension/accompanying modules under `github.com/jwx-go/*/v4`.
  Users opt in by importing the modules they need:

  - `github.com/jwx-go/asmbase64/v4` — assembly-optimized base64 backend (was `jwx_asmbase64` build tag)
  - `github.com/jwx-go/compsig/v4` — hybrid composite signatures pairing ML-DSA with classical algorithms (new, draft-ietf-jose-pq-composite-sigs)
  - `github.com/jwx-go/ed448/v4` — EdDSA with Ed448 curve (was `jwa.EdDSAEd448()` / `jwa.Ed448()` in the main module)
  - `github.com/jwx-go/es256k/v4` — ES256K/secp256k1 support (was `jwx_es256k` build tag)
  - `github.com/jwx-go/examples/v4` — examples (was `examples/` directory in the main repo)
  - `github.com/jwx-go/jwkfetch/v4` — all HTTP-based JWKS retrieval: one-shot fetching, whitelists, and background-refreshed caches (replaces `jwk.Fetch` / `jwk.Cache` and removes the `net/http`/`httprc` dependency from core jwx)
  - `github.com/jwx-go/mldsa/v4` — ML-DSA signature support (new, FIPS 204)
  - `github.com/jwx-go/mlkem/v4` — ML-KEM key encapsulation for JWE (new, FIPS 203, draft-ietf-jose-pqc-kem)
  - `github.com/jwx-go/reddy-pqchpke/v4` — hybrid PQ HPKE (X25519 + ML-KEM-768 via X-Wing; draft-reddy-cose-jose-pqc-hybrid-hpke, very early)
  - `github.com/jwx-go/x448/v4` — X448 ECDH-ES key agreement and HPKE with DHKEM(X448) (new)

  In addition, `github.com/jwx-go/jwxmigrate` provides a CLI tool that applies
  mechanical v3→v4 code fixes and reports issues requiring manual review.

  Build-tag gating (`jwx_goccy`, `jwx_es256k`, `jwx_asmbase64`) is no longer supported.

* `ReadFile()` has been removed from all packages. Use `ParseFS(fs.FS, path, ...options)`
  instead, which accepts an `fs.FS` and a path within that filesystem.

* Generic free functions have been added across all packages for type-safe field access:

  ```go
  // v3
  var kid string
  key.Get("kid", &kid)

  // v4
  kid, err := jwk.Get[string](key, "kid")
  ```

  `Get[T]` is available in `jwk`, `jwt`, `jws`, and `jwe`.

* `RegisterCustomField[T](name)` and `RegisterCustomDecoder[T](name, dec)` are now
  generic, replacing the previous untyped registration functions. Available in `jwk`,
  `jwt`, `jws`, and `jwe`.

* Internal JSON handling now uses `encoding/json/v2`.

* `jwx.DecoderSettings()` has been renamed to `jwx.Settings()` to match the
  sub-package convention. `jwx.Settings(jwx.WithUseNumber(true))` preserves
  JSON numbers as `json.Number` in private/custom fields.

* `jwx.SetBase64Encoder()` and `jwx.SetBase64Decoder()` have been removed.
  Configure the base64 backend through `jwx.Settings()` instead:
  `jwx.Settings(jwx.WithBase64Encoder(enc), jwx.WithBase64Decoder(dec))`.
  The `jwx.Base64Encoder` / `jwx.Base64Decoder` interface types are unchanged.

* `github.com/lestrrat-go/blackmagic` has been removed. Reflection-based conversions
  have been replaced with generics.

* The option infrastructure (`github.com/lestrrat-go/option`) has been upgraded from v2
  to v3, which uses generics. Option values are now retrieved via `option.MustGet[T](opt)`
  instead of type-asserting `opt.Value()`.

## JWK

* `jwk.PublicSetOf` now returns an error if the input set contains a
  symmetric (`oct`) key, because the "public" form of a symmetric key
  would be the secret itself — publishing the result (e.g. as
  `/.well-known/jwks.json`) would leak the HMAC secret. Callers who
  genuinely want the legacy pass-through can opt in with
  `jwk.PublicSetOf(set, jwk.WithAllowSymmetric(true))`. The signature
  is now variadic (`PublicSetOf(v Set, options ...PublicSetOption)`),
  so existing call sites compile unchanged.

  `jwk.PublicKeyOf` on a single symmetric key is unchanged — it still
  returns the key as-is, matching its documented behavior.

* `jwk.Import()` is now generic: `jwk.Import[T Key](raw any) (T, error)`.
  This replaces the previous `jwk.Import()` which returned an untyped `jwk.Key`.

* `jwk.Export()` is now generic: `jwk.Export[T any](key Key) (T, error)`.

* `jwk.ExportAll[T any](set Set) ([]T, error)` is new — the plural counterpart
  to `jwk.Export[T]`. Exports every key in a [Set], preserving insertion order,
  and fails fast on the first mismatch. For a heterogeneous set, use
  `T = any`; each element's dynamic type matches its source key's raw form.

* `jwk.ParseKey()` is now generic: `jwk.ParseKey[T Key](data []byte, ...options) (T, error)`.

* `jwk.Fetch()` and `jwk.Cache` have both been removed from the main module, along
  with every other HTTP-touching entry point. The core `jwk` package no longer
  depends on `net/http` or `httprc`. All HTTP-backed JWKS retrieval — one-shot
  fetching, whitelists, and background-refreshed caches — now lives in
  `github.com/jwx-go/jwkfetch/v4`.

* `jwk.RegisterProbeField()` is now generic: `jwk.RegisterProbeField[T any](name, jsonKey string)`.
  This replaces the previous `reflect.StructField`-based API:

  ```go
  // v3
  jwk.RegisterProbeField(reflect.StructField{Name: "MyHint", Type: reflect.TypeOf(""), Tag: `json:"my_hint"`})

  // v4
  jwk.RegisterProbeField[string]("MyHint", "my_hint")
  ```

* RSA JWK validation is now enforced consistently across JSON parse, JWKS parse,
  PEM/X.509 parse, and `jwk.Import()`. Keys with moduli smaller than 2048 bits
  or unsafe public exponents are now rejected by default. Compatibility knobs are available via
  `jwk.Settings(jwk.WithMinRSAModulusBits(...), jwk.WithMinRSAPublicExponent(...))`.

* The `AKP` key type (Algorithm Key Pair, RFC 9802) has been added, exposed as
  `jwa.AKP()` with `jwk.AKPPublicKey` / `jwk.AKPPrivateKey`. This is a generic
  key type for post-quantum algorithms and is used by both ML-DSA (signature)
  and ML-KEM (key encapsulation) support. ML-KEM key import/export lives in
  the `github.com/jwx-go/mlkem` companion module; only the generic AKP
  machinery is in core jwx.

* `jwk.Set` now supports range-over-func iteration:

  ```go
  for idx, key := range set.All() {
      // ...
  }
  ```

  `(jwk.Set).All()` returns `iter.Seq2[int, Key]` for iterating over keys.
  `(jwk.Set).Fields()` returns `iter.Seq2[string, any]` for iterating over non-key
  fields in the set (e.g. custom fields).

## JWT

* `jwt.Parse()` with a single `jwt.WithKey(alg, key)` option and compact JWS input now
  takes a fast path that bypasses format detection, option conversion, and the nested
  decode loop, going directly to `jws.VerifyCompactFast()`. This reduces allocations
  and improves parse+verify throughput.

* `jws.VerifyCompactFast()` now uses strict base64url decoding (RFC 7515, no padding)
  instead of auto-detecting the encoding variant. This eliminates per-decode scanning
  overhead and allows signature buffer pooling.

* Added `jwt.WithStrictBase64Encoding(bool)` option (default: true). Set to false to
  fall back to auto-detecting base64 encoding for compatibility with non-conformant
  providers. When false, the fast path is bypassed.

* `(jwt.Token).Claims()` returns `iter.Seq2[string, any]` for range-over-func iteration:

  ```go
  for name, value := range token.Claims() {
      // ...
  }
  ```

* Validation errors are now structured and collect all failures instead of returning on
  the first error. `jwt.Validate()` returns errors that can be inspected with
  `errors.As` for specific types such as `jwt.TokenExpiredError`, `jwt.TokenNotYetValidError`,
  and `jwt.InvalidIssuedAtError`, each carrying structured fields (e.g. `Expiration`,
  `Now`, `Skew`).

## JWS

* The legacy signer/verifier system has been removed. The entire `jws/legacy/` package
  is gone.

* `jws.SplitCompact()`, `jws.SplitCompactString()`, and `jws.SplitCompactReader()`
  have been removed. Use `jwsbb.SplitCompact()` and friends directly.

* `jws.RegisterSigner()` and `jws.RegisterVerifier()` now require the typed
  `Signer2` / `Verifier2` interfaces. The old untyped factory signatures are no
  longer accepted.

* ML-DSA (FIPS 204) signature support is available via the `github.com/jwx-go/mldsa/v4`
  extension module.

## JWE

* `jwe.WithLegacyHeaderMerging()` has been removed. The default behavior is now
  spec-compliant: per-recipient headers are not merged into the protected header
  during flattened JSON serialization.

* **PBES2 iteration count defaults raised to OWASP 2023 levels.** v3 shipped
  `p2c=10000` on both the encrypt and decrypt sides, which is ~60x below
  current OWASP guidance for PBKDF2-HMAC-SHA256. v4 changes:

  - `jwe.Encrypt` with a PBES2 key now emits per-variant defaults:
    600,000 for `PBES2-HS256+A128KW`, 210,000 for `PBES2-HS384+A192KW`,
    and 210,000 for `PBES2-HS512+A256KW`. Override per call with
    `jwe.WithPBES2Count`; override globally with
    `jwe.Settings(jwe.WithPBES2Count(...))`. Passing `0` to `Settings`
    restores the per-variant defaults.
  - `jwe.Decrypt` accepts `p2c` up to 1,000,000 by default (v3 was 10,000).
    This lets jwx interop with modern producers (go-jose, jose.js,
    python-jose) configured to current guidance. Clamp lower with
    `jwe.WithMaxPBES2Count` if your deployment needs tighter latency.

  **Migration note.** These changes are v4-only — v3 is not being updated.
  Interop consequences:

  - v4 encrypt → v3 decrypt: v3's 10,000 cap will reject v4 output.
    Either bump v3's cap (`jwe.Settings(jwe.WithMaxPBES2Count(600000))`)
    or have v4 produce a lower count explicitly via
    `jwe.WithPBES2Count(10000)` during the rollout window.
  - v3 encrypt → v4 decrypt: unaffected — v4's cap is higher, not lower.
  - v3→v4 upgrade at rest: tokens sitting in storage with `p2c=10000`
    still decrypt under v4 defaults.

  **Security note on DoS.** PBES2 decryption runs PBKDF2 over a
  caller-controlled iteration count. v4's higher cap does *not* widen
  who can force PBKDF2 work: `jwe.Decrypt` only reaches the PBES2 code
  path when the caller explicitly configures a password key via
  `jwe.WithKey(jwa.PBES2_*..., passwordBytes)`. Callers who don't use
  PBES2 are unaffected. Callers who *do* accept PBES2 on an untrusted
  input surface have exposed a password-check-equivalent cost per
  request (tens of milliseconds of CPU at the default cap) and MUST
  rate-limit accordingly — the library cannot do this for them. Use
  `jwe.WithMaxPBES2Count` to clamp the cap lower if needed.

* ML-KEM (FIPS 203) key encapsulation for JWE is provided as a companion
  module at [`github.com/jwx-go/mlkem`](https://github.com/jwx-go/mlkem).
  Importing it for side effects registers `ML-KEM-768`, `ML-KEM-1024`,
  `ML-KEM-768+A192KW`, and `ML-KEM-1024+A256KW` per draft-ietf-jose-pqc-kem.
  ML-KEM lives in a companion (rather than core jwx) because the JOSE binding
  is still an Internet-Draft. Core jwx exposes a `jwebb.MLKEMKeyEncrypter` /
  `jwebb.MLKEMKeyDecrypter` extension hook that the companion plugs into.

* HPKE key encryption (draft-ietf-jose-hpke-encrypt-16) is now supported for JWE.
  Six algorithms are available: `HPKE-0-KE` through `HPKE-7-KE`, covering
  DHKEM(P-256), DHKEM(P-384), DHKEM(P-521), and DHKEM(X25519) with various
  KDF/AEAD combinations. Uses Go 1.26 `crypto/hpke`. X448-based HPKE is
  available via the `github.com/jwx-go/x448/v4` companion module. A very early
  hybrid PQ HPKE variant (X25519 + ML-KEM-768) is available via
  `github.com/jwx-go/reddy-pqchpke/v4`. **These are based on draft specifications
  and the APIs are not yet stable.**
