# Incompatible Changes from v3 to v4

These are changes that are incompatible with the v3.x.x version.

# Detailed list of changes

## Module

* This module now requires Go 1.26

* The number of dependencies in the main module has been trimmed to a bare minimum.
  Features that were previously built into the main module or gated behind build tags
  are now provided by extension/accompanying modules under `github.com/jwx-go/*/v4`.
  Users opt in by importing the modules they need:

  - `github.com/jwx-go/es256k/v4` — ES256K/secp256k1 support (was `jwx_es256k` build tag)
  - `github.com/jwx-go/jwkcache/v4` — JWK Set caching via HTTP (was `jwk.Cache` in the main module)
  - `github.com/jwx-go/mldsa/v4` — ML-DSA signature support (new)
  - `github.com/jwx-go/examples/v4` — examples (was `examples/` directory in the main repo)

  Build-tag gating (`jwx_goccy`, `jwx_es256k`) is no longer supported.

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

* `github.com/lestrrat-go/blackmagic` has been removed. Reflection-based conversions
  have been replaced with generics.

* The option infrastructure (`github.com/lestrrat-go/option`) has been upgraded from v2
  to v3, which uses generics. Option values are now retrieved via `option.MustGet[T](opt)`
  instead of type-asserting `opt.Value()`.

## JWK

* `jwk.Import()` is now generic: `jwk.Import[T Key](raw any) (T, error)`.
  This replaces the previous `jwk.Import()` which returned an untyped `jwk.Key`.

* `jwk.Export()` is now generic: `jwk.Export[T any](key Key) (T, error)`.

* `jwk.ParseKey()` is now generic: `jwk.ParseKey[T Key](data []byte, ...options) (T, error)`.

* `jwk.Cache` has been removed from the main module. Use `github.com/jwx-go/jwkcache/v4`
  instead.

* ML-KEM key type (`jwk.AKP`) has been added for post-quantum key encapsulation
  (FIPS 203). This supports ML-KEM-768 and ML-KEM-1024.

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

* ML-KEM (FIPS 203) key encapsulation is now supported for JWE. The supported
  algorithms include `ML-KEM-768` and `ML-KEM-1024` (standalone), as well as
  hybrid variants `ML-KEM-768+A192KW` and `ML-KEM-1024+A256KW`.
