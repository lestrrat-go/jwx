# Migrating from jwx v3 to v4

This guide covers all breaking changes between `github.com/lestrrat-go/jwx/v3` and `github.com/lestrrat-go/jwx/v4`.

The [`jwxmigrate`](https://github.com/jwx-go/jwxmigrate) tool can apply mechanical fixes automatically and report issues that require manual review:

    go install github.com/jwx-go/jwxmigrate/v4@latest

    # Apply all mechanical fixes in-place (import rewrites, renames, etc.)
    jwxmigrate --fix ./...

    # Then check what remains (items needing manual judgment)
    jwxmigrate ./...

The recommended workflow is to run `--fix` first, then address the remaining findings.

Additional options:

    # JSON output (for CI pipelines / AI coding agents)
    jwxmigrate --format json

    # Only show mechanically fixable items
    jwxmigrate --mechanical

    # Check a specific rule
    jwxmigrate --rule import-v3-to-v4

Exit codes: 0 = migration complete, 1 = v3 patterns remain, 2 = error.

Text output labels each finding as `(auto)` or `(manual)`, with migration notes and before/after examples. JSON output adds precise source locations (`line`, `col`, `end_line`, `end_col`) for programmatic use.

## Prerequisites

- Go 1.26.0 or later
- Set `GOEXPERIMENT=jsonv2` in your build environment
- Update `go.mod`: change module requirement to `github.com/lestrrat-go/jwx/v4`

## Quick Reference

| v3 | v4 | Notes |
|----|-----|-------|
| `import ".../jwx/v3/..."` | `import ".../jwx/v4/..."` | All packages |
| `.Get(name, &dst)` | `.Field(name) (any, bool)` or `pkg.Get[T](obj, name)` | Key, Token, Headers |
| `ReadFile(path, opts...)` | `ReadFile(path, opts...)` *(still works, deprecated)* or `ParseFS(fsys, path, opts...)` | All packages; `ParseFS` is the preferred replacement |
| `RegisterCustomField(name, obj)` | `RegisterCustomField[T](name)` | All packages |
| `jwk.RegisterProbeField(reflect.StructField{...})` | `jwk.RegisterProbeField[T](name, jsonKey)` | No `reflect` import needed |
| `jwk.Import(raw)` | `jwk.Import[T](raw)` | Generic return type |
| `jwk.ParseKey(data)` | `jwk.ParseKey(data)` *(unchanged — returns `jwk.Key`)* / `jwk.ParseKeyAs[T](data)` | Typed subtype moved to `ParseKeyAs[T]` |
| `jwk.RegisterX509Decoder(ident, d)` | `jwkbb.RegisterX509Decoder[T](blockType, d)` | Moved to `jwk/jwkbb` and keyed by the PEM block type string. `T` is the decoder's concrete return type. Returns error on empty blockType or nil decoder instead of panicking; registering the same blockType twice overwrites. |
| `jwk.UnregisterX509Decoder(ident)` | `jwkbb.UnregisterX509Decoder(blockType)` | Takes the PEM block type rather than an opaque ident |
| `jwk.X509Decoder` / `jwk.X509DecodeFunc` | `jwkbb.X509Decoder[T]` / `jwkbb.X509DecodeFunc[T]` | Moved to `jwk/jwkbb` and made generic; `T` is the decoder's return type |
| *(not available)* | `jwkbb.RegisterX509Encoder[T](e)` / `jwkbb.UnregisterX509Encoder[T]()` / `jwkbb.X509Encoder[T]` / `jwkbb.X509EncodeFunc[T]` | New in v4: custom PEM encoders for `jwkbb.EncodePEM`, keyed by Go type (e.g. PQC key formats) |
| `jwk.PEMDecoder` / `jwk.PEMDecodeFunc` / `jwk.PEMEncoder` / `jwk.PEMEncodeFunc` / `jwk.NewPEMDecoder()` | *(removed)* | Plumbing types removed; register a custom decoder through `jwkbb.RegisterX509Decoder` instead |
| `jwk.WithPEMDecoder(d)` | *(removed)* | Use `jwkbb.RegisterX509Decoder(ident, d)` to install a custom PEM block decoder globally |
| `jwk.WithPEM(true)` | `jwk.WithX509(true)` | Single option for "input is PEM-framed X.509"; `WithPEM` was a pre-release alias scheduled for removal |
| `jwk.EncodePEM(v)` | `jwkbb.EncodePEM(raw)` | Unwrap `jwk.Key` with `jwk.Export[any]` first; accepts one or more raw keys |
| `jwk.Pem(keyOrSet)` | `jwkbb.EncodePEM(jwk.ExportAll[any](set)...)` | Iterate a `jwk.Set` into raw keys via `jwk.ExportAll[any]`, then pass variadically |
| `jwk.NewCache(ctx, client)` | `jwkfetch.NewCache(ctx, client)` | Extension module (see Recipe 6) |
| `jwk.Fetch(ctx, url, opts...)` | `jwkfetch.NewClient(opts...).Fetch(ctx, url)` | Extension module (see Recipe 6) |
| `jwk.WithHTTPClient(c)` | `jwkfetch.WithHTTPClient(c)` | Extension module |
| `jwk.WithFetchWhitelist(w)` | `jwkfetch.WithWhitelist(w)` | Extension module; default tightened to deny-all |
| `jwk.WithMaxFetchBodySize(n)` | `jwkfetch.WithMaxBodySize(n)` | Extension module |
| `jwk.InsecureWhitelist{}` / `jwk.MapWhitelist` / `jwk.RegexpWhitelist` / `jwk.WhitelistFunc` | `jwkfetch.InsecureWhitelist{}` / `jwkfetch.MapWhitelist` / `jwkfetch.RegexpWhitelist` / `jwkfetch.WhitelistFunc` | Extension module |
| `jwk.WhitelistError()` | `jwkfetch.WhitelistError()` | Extension module |
| `jwk.Fetcher` | `jwk.Fetcher` (unchanged name, new shape: `Fetch(ctx, url) (Set, error)` — no variadic options) | Core interface, no in-package implementation |
| `jwk.PublicSetOf(set)` (silent pass-through for symmetric keys) | `jwk.PublicSetOf(set)` (returns error if any oct key is present) / `jwk.PublicSetOf(set, jwk.WithAllowSymmetric(true))` | Behavioral. Default-rejects sets containing symmetric keys to prevent accidental publication of secret material (e.g. as `/.well-known/jwks.json`). Pass `WithAllowSymmetric(true)` to opt into the v3 pass-through. |
| `jws.WithVerifyAuto(f, fetchOpts...)` | `jws.WithVerifyAuto(f)` | Variadic options dropped; nil fetcher now errors instead of silently using `jwk.Fetch` |
| `jwt.WithVerifyAuto(f, fetchOpts...)` | `jwt.WithVerifyAuto(f)` | Same as jws |
| `jws.Signer2` | `jws.Signer` | Interface renamed |
| `jws.Verifier2` | `jws.Verifier` | Interface renamed |
| `jws.RegisterSigner(alg, any)` | `jws.RegisterSigner(alg, Signer)` | Typed parameter |
| `jws.RegisterVerifier(alg, any)` | `jws.RegisterVerifier(alg, Verifier)` | Typed parameter |
| `jwx.DecoderSettings(jwx.WithUseNumber(true))` | `jwx.Settings(jwx.WithUseNumber(true))` | API renamed |
| `jwt.Settings(...)` / `jws.Settings(...)` / `jwe.Settings(...)` / `cert.Settings(...)` / `jwx.Settings(...)` / `jwk.Settings(...)` (void) | same name, now returns `error` | Invalid values return an error instead of panicking (jwx validates nil encoder/decoder; others validate their size limits; jwk reserves the return for future validation) |
| `errors.Is(err, jwt.TokenExpiredError())` | `errors.Is(err, jwt.TokenExpiredError{})` | Sentinel funcs → struct types; see Recipe 13 |
| `-tags=jwx_goccy` | _(removed)_ | json/v2 is the only backend |
| `-tags=jwx_es256k` | `github.com/jwx-go/es256k/v4` | Extension module |
| `-tags=jwx_asmbase64` | `github.com/jwx-go/asmbase64/v4` | Extension module |
| `jwa.ES256K()` | `es256k.ES256K()` | `import "github.com/jwx-go/es256k/v4"` |
| `jwa.Ed448()` | `ed448.Curve()` | `import "github.com/jwx-go/ed448/v4"` |
| `jwa.EdDSAEd448()` | `ed448.EdDSAEd448()` | `import "github.com/jwx-go/ed448/v4"` |
| `jwt.TokenFilter` / `jws.HeaderFilter` / `jwe.HeaderFilter` / `jwk.KeyFilter` | `jwxfilter.Filter[jwt.Token]` / `Filter[jws.Headers]` / `Filter[jwe.Headers]` / `Filter[jwk.Key]` | Moved to companion `github.com/jwx-go/jwxfilter/v4`; collapsed into one generic interface. |
| `jwt.NewClaimNameFilter(...)` | `jwtfilter.ByName(...)` | Moved to `github.com/jwx-go/jwxfilter/v4/jwtfilter`. |
| `jwt.StandardClaimsFilter()` | `jwtfilter.Standard()` | Moved to `github.com/jwx-go/jwxfilter/v4/jwtfilter`. |
| `jws.NewHeaderNameFilter(...)` | `jwsfilter.ByName(...)` | Moved to `github.com/jwx-go/jwxfilter/v4/jwsfilter`. |
| `jws.StandardHeadersFilter()` | `jwsfilter.Standard()` | Moved to `github.com/jwx-go/jwxfilter/v4/jwsfilter`. |
| `jwe.NewHeaderNameFilter(...)` | `jwefilter.ByName(...)` | Moved to `github.com/jwx-go/jwxfilter/v4/jwefilter`. |
| `jwe.StandardHeadersFilter()` | `jwefilter.Standard()` | Moved to `github.com/jwx-go/jwxfilter/v4/jwefilter`. |
| `jwk.NewFieldNameFilter(...)` | `jwkfilter.ByName(...)` | Moved to `github.com/jwx-go/jwxfilter/v4/jwkfilter`. |
| `jwk.RSAStandardFieldsFilter()` / `ECDSAStandardFieldsFilter()` / `OKPStandardFieldsFilter()` / `SymmetricStandardFieldsFilter()` / `AKPStandardFieldsFilter()` | `jwkfilter.RSAStandard()` / `ECDSAStandard()` / `OKPStandard()` / `SymmetricStandard()` / `AKPStandard()` | Moved to `github.com/jwx-go/jwxfilter/v4/jwkfilter`. |
| `openid.StandardClaimsFilter()` | `openidfilter.Standard()` | Moved to `github.com/jwx-go/jwxfilter/v4/openidfilter`. |
| `transform.AsMap` / `transform.Mappable` | `jwxfilter.AsMap` / `jwxfilter.Mappable` | Moved to `github.com/jwx-go/jwxfilter/v4` (root package). |
| `transform.FilterLogic` / `FilterLogicFunc` / `Filterable` / `NameBasedFilter` / `NewNameBasedFilter` / `Apply` / `Reject` | _(removed from public API)_ | These were experimental internal primitives; the companion keeps equivalents unexported. Use a `<type>filter.ByName(...)` constructor instead. |

## Migration Recipes

### Recipe 1: Update Import Paths

Find and replace all v3 imports:

```go
// Before
import (
    "github.com/lestrrat-go/jwx/v3/jwt"
    "github.com/lestrrat-go/jwx/v3/jwk"
    "github.com/lestrrat-go/jwx/v3/jws"
    "github.com/lestrrat-go/jwx/v3/jwe"
    "github.com/lestrrat-go/jwx/v3/jwa"
)

// After
import (
    "github.com/lestrrat-go/jwx/v4/jwt"
    "github.com/lestrrat-go/jwx/v4/jwk"
    "github.com/lestrrat-go/jwx/v4/jws"
    "github.com/lestrrat-go/jwx/v4/jwe"
    "github.com/lestrrat-go/jwx/v4/jwa"
)
```

### Recipe 2: Field Access (Get → Field / Get[T])

The `Get(name string, dst any) error` method is replaced across all interfaces.

```go
// Before: output parameter pattern
var kid string
if err := key.Get("kid", &kid); err != nil {
    return err
}

var exp time.Time
if err := token.Get(jwt.ExpirationKey, &exp); err != nil {
    return err
}

// After: generic accessor (preferred)
kid, err := jwk.Get[string](key, "kid")
if err != nil {
    return err
}

exp, err := jwt.Get[time.Time](token, jwt.ExpirationKey)
if err != nil {
    return err
}

// After: Field() for simple existence checks
if v, ok := key.Field("kid"); ok {
    kid := v.(string)
    // ...
}
```

### Recipe 3: JWK Import with Generics

```go
// Before: Import + type assertion
key, err := jwk.Import(rsaPrivateKey)
if err != nil {
    return err
}
rsaKey, ok := key.(jwk.RSAPrivateKey)
if !ok {
    return errors.New("expected RSA key")
}

// After: generic Import
rsaKey, err := jwk.Import[jwk.RSAPrivateKey](rsaPrivateKey)
if err != nil {
    return err // includes type mismatch
}

// If you don't know the concrete type, use jwk.Key:
key, err := jwk.Import[jwk.Key](someRawKey)
```

### Recipe 4: File Reading

`ReadFile` is retained for source compatibility with v3 but is now deprecated.
New code should use `ParseFS`, which takes an explicit `fs.FS` and works with
`os.DirFS`, `embed.FS`, `testing/fstest`, or any other filesystem.

```go
// v3 code keeps working unchanged (deprecated):
token, err := jwt.ReadFile("path/to/token.jwt")
set, err := jwk.ReadFile("path/to/keys.json")
msg, err := jws.ReadFile("path/to/message.jws")

// Preferred in v4:
token, err := jwt.ParseFS(os.DirFS("."), "path/to/token.jwt")
set, err := jwk.ParseFS(os.DirFS("."), "path/to/keys.json")
msg, err := jws.ParseFS(os.DirFS("."), "path/to/message.jws")
```

Note: `os.DirFS(".")` rejects absolute paths and paths containing `..`
(per `fs.ValidPath`). If you need to read by absolute path, either keep using
`ReadFile` or call `ParseFS(os.DirFS("/"), path[1:])`.

### Recipe 5: Custom Signer/Verifier

```go
// Before: implement Signer2 with Algorithm()
type MySigner struct{}
func (s MySigner) Algorithm() jwa.SignatureAlgorithm { return jwa.RS256() }
func (s MySigner) Sign(key any, payload []byte) ([]byte, error) {
    // ...
}
jws.RegisterSigner(jwa.RS256(), MySigner{}) // accepted as Signer2

// After: implement Signer (no Algorithm method)
type MySigner struct{}
func (s MySigner) Sign(key any, payload []byte) ([]byte, error) {
    // ...
}
jws.RegisterSigner(jwa.RS256(), MySigner{})
```

### Recipe 6: HTTP JWK Set retrieval (jwk.Fetch, jwk.Cache, jwk.Whitelist)

All HTTP-based JWK Set retrieval has moved out of the core `jwk` package into a single companion: [`github.com/jwx-go/jwkfetch/v4`](https://github.com/jwx-go/jwkfetch). The main jwx/v4 module no longer depends on `net/http` or `httprc`. `jwkfetch` supersedes both the v3 `jwk.Fetch` / `jwk.Whitelist` / `jwk.HTTPClient` surface **and** the standalone v3 `jwx-go/jwkcache` companion.

jwkfetch offers two complementary types, both implementing `jwk.Fetcher`:

- `jwkfetch.Client` — one-shot fetcher with whitelist, body-size cap, parse options. For `jku`-style verification.
- `jwkfetch.Cache` — background-refreshed JWKS store backed by `httprc`. For a small trusted set of issuer endpoints.

Both are **closed structs** constructed via functional options. The core `jwk.Fetcher` interface is now options-free:

```go
type Fetcher interface {
    Fetch(ctx context.Context, url string) (Set, error)
}
```

> **⚠️ SECURITY: jku migration can introduce SSRF if you forget the whitelist.**
>
> In v3, `jws.WithVerifyAuto` prepended an implicit deny-all whitelist in front of the caller's fetch options. A v3 call site that passed `jws.WithVerifyAuto(nil, opts...)` *without* an explicit whitelist was rejected at verification time — the library failed closed.
>
> In v4, there is no implicit wrapper. `jws.WithVerifyAuto` / `jwt.WithVerifyAuto` take only a `jwk.Fetcher`, and `jwkfetch.NewClient()` with no `WithWhitelist` **permits every URL**. The naive migration
>
> ```go
> // v3
> jws.Verify(signed, jws.WithVerifyAuto(nil, jwk.WithFetchWhitelist(wl)))
>
> // v4 — LOOKS RIGHT, IS NOT: the whitelist is gone
> jws.Verify(signed, jws.WithVerifyAuto(jwkfetch.NewClient()))
> ```
>
> compiles, runs, and silently turns the verifier into an SSRF primitive: the `jku` header is attacker-controlled, so the library will happily fetch any URL an attacker puts there, and accept the returned keys as "the issuer's keys." The jwx library cannot detect this at runtime — the permissive-`Client` case is a valid configuration for trusted hard-coded URLs, and jwx has no way to tell the two use cases apart.
>
> **You MUST audit every `jws.WithVerifyAuto` / `jwt.WithVerifyAuto` call site during migration** and ensure the `jwkfetch.Client` you pass has a restrictive `WithWhitelist` (a `MapWhitelist`, `RegexpWhitelist`, or custom `WhitelistFunc` constrained to your known issuer set):
>
> ```go
> // v4 — correct
> client := jwkfetch.NewClient(
>     jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add("https://issuer.example/jwks.json")),
> )
> jws.Verify(signed, jws.WithVerifyAuto(client))
> ```
>
> `jwkfetch.Client` applies the whitelist to both the initial URL and every HTTP redirect target, so a hostile JWKS host cannot 302 into an off-allowlist URL. This redirect-hop enforcement only applies when the configured `HTTPClient` is a `*http.Client`; if you supply a custom transport, you are responsible for policing redirects yourself.
>
> If you migrate a `RegexpWhitelist`, **anchor your patterns** — they are **not** anchored for you. `example\.com` matches anywhere in the URL and also allows `https://example.com.attacker.com/evil`, reopening the SSRF / key-substitution hole. Write `^https://example\.com/` (anchor the start with `^`, escape the dots, terminate the host with `/`), or use `MapWhitelist` when the issuer URLs are known exactly.
>
> `jws.WithVerifyAuto(nil)` / `jwt.WithVerifyAuto(nil)` is no longer supported — both error at jku-verification time rather than silently using any default.

**Default behavior is equivalent to v3 for trusted, hard-coded URLs.** Both v3's `jwk.Fetch()` and v4's `jwkfetch.NewClient().Fetch()` permit every URL by default — the right choice when the URL is a compile-time constant or comes from trusted configuration. You generally do not need to pass `WithWhitelist` to migrate a hard-coded-URL call site. The SSRF risk above is specific to `jku`-style verification, where the URL originates in the untrusted JWS header.

```go
// Before — one-shot jwk.Fetch
import "github.com/lestrrat-go/jwx/v3/jwk"

set, err := jwk.Fetch(ctx, url,
    jwk.WithHTTPClient(myClient),
    jwk.WithFetchWhitelist(jwk.NewMapWhitelist().Add(url)),
)

// After — one-shot jwkfetch.Client
import "github.com/jwx-go/jwkfetch/v4"

client := jwkfetch.NewClient(
    jwkfetch.WithHTTPClient(myClient),
    jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add(url)),
)
set, err := client.Fetch(ctx, url)
```

```go
// Before — background-refreshed cache (v3 jwk.Cache)
import (
    "github.com/lestrrat-go/httprc/v3"
    "github.com/lestrrat-go/jwx/v3/jwk"
)

cache, _ := jwk.NewCache(ctx, httprc.NewClient())
cache.Register(ctx, url, jwk.WithMinRefreshInterval(15*time.Minute))
set, _ := cache.Lookup(ctx, url)

// After — jwkfetch.Cache (same idea, new module)
import (
    "github.com/jwx-go/jwkfetch/v4"
    "github.com/lestrrat-go/httprc/v3"
)

cache, _ := jwkfetch.NewCache(ctx, httprc.NewClient())
_ = cache.Register(ctx, url, jwkfetch.WithMinInterval(15*time.Minute))
set, _ := cache.Lookup(ctx, url)
```

```go
// Before — wiring into jws.Verify via jku
_, err := jws.Verify(signed, jws.WithVerifyAuto(nil, jwk.WithFetchWhitelist(wl), jwk.WithHTTPClient(c)))

// After — build the fetcher once, pass it
fetcher := jwkfetch.NewClient(
    jwkfetch.WithWhitelist(wl),
    jwkfetch.WithHTTPClient(c),
)
_, err := jws.Verify(signed, jws.WithVerifyAuto(fetcher))
```

`Cache.Client.Whitelist` is not consulted by Cache — registration is the trust boundary for cached URLs. If you need per-fetch whitelist enforcement, use `Client` via `jwk.Fetcher` instead.

### Recipe 7: Custom Field Registration

The field type is now carried by the type parameter instead of a sample
value, so the second argument to `RegisterCustomField` is gone.

```go
// Before
jwt.RegisterCustomField("my-field", time.Time{})
jwk.RegisterCustomField("x-custom", "")

// After
jwt.RegisterCustomField[time.Time]("my-field")
jwk.RegisterCustomField[string]("x-custom")
```

`RegisterCustomField[T]` decodes the claim with stock `json.Unmarshal`
into `T`. If you previously relied on the sample-value argument to drive
custom parsing (for example, a `time.Time` that doesn't round-trip
through RFC 3339), use `RegisterCustomDecoder[T]` instead — it takes a
function that receives the raw JSON bytes and returns a `T`:

```go
jwt.RegisterCustomDecoder(`x-birthday`, jwt.CustomDecodeFunc[time.Time](func(data []byte) (time.Time, error) {
    var s string
    if err := json.Unmarshal(data, &s); err != nil {
        return time.Time{}, err
    }
    return time.Parse(time.RFC1123, s)
}))
```

`RegisterCustomDecoder` is available in `jwt`, `jws`, `jwe`, `jwk`, and
`jwt/openid`.

### Recipe 8: JWK Probe Field Registration

```go
// Before
jwk.RegisterProbeField(reflect.StructField{
    Name: "MyHint",
    Type: reflect.TypeOf(""),
    Tag:  `json:"my_hint"`,
})

// After
jwk.RegisterProbeField[string]("MyHint", "my_hint")
```

### Recipe 9: ES256K / Ed448 / Assembly Base64

Features formerly enabled via build tags are now extension modules.

```go
// Before: build with -tags=jwx_es256k
// jwa.ES256K() was available automatically

// After: import the extension module (registers via init())
import "github.com/jwx-go/es256k/v4"

// Use es256k.ES256K() instead of jwa.ES256K()
// Use es256k.Secp256k1() instead of jwa.Secp256k1()
```

If you only need registration (no direct references to the algorithm identifiers), use a blank import:

```go
import _ "github.com/jwx-go/es256k/v4"
```

Same pattern for Ed448 and assembly base64:

```go
import "github.com/jwx-go/ed448/v4"   // ed448.EdDSAEd448(), ed448.Curve()
import _ "github.com/jwx-go/asmbase64/v4" // registration only
```

### Recipe 10: Custom Key Importer

```go
// Before (v3)
jwk.RegisterKeyImporter(&myKeyType{}, jwk.KeyImportFunc(func(raw any) (jwk.Key, error) {
    src, ok := raw.(*myKeyType)
    if !ok {
        return nil, fmt.Errorf("expected *myKeyType, got %T", raw)
    }
    // ... convert
}))

// After (v4): RegisterKeyImporter takes a jwk.KeyImporter[T]; use
// jwk.KeyImportFunc[T] to adapt a typed function. The outer type
// parameter is inferred from the adapter's typed Import method.
jwk.RegisterKeyImporter(jwk.KeyImportFunc[*myKeyType](func(src *myKeyType) (jwk.Key, error) {
    // The interface is typed, so src is *myKeyType in the body —
    // no manual assertion.
    // ... convert
}))
```

### Recipe 11: Iterating Over Sets and Tokens

```go
// Before: index-based loop for jwk.Set
for i := 0; i < set.Len(); i++ {
    key, ok := set.Key(i)
    if !ok {
        continue
    }
    // use key
}

// After: range over iterator
for _, key := range set.All() {
    // use key
}

// Before: iterate private parameters (no direct API)

// After: range over iterator
for name, value := range set.Fields() {
    // use name, value
}

// Before: iterate token claims
for _, k := range token.Keys() {
    var v any
    _ = token.Get(k, &v)
    // use k, v
}

// After: range over iterator
for name, value := range token.Claims() {
    // use name, value
}
```

### Recipe 12: JWE Package

The `jwe` package follows the same cross-cutting changes as other packages (Recipes 1-4, 7, 10 apply). One additional removal:

```go
// Before: legacy header merging (v2-era compat)
jwe.Encrypt(payload, jwe.WithKey(alg, key), jwe.WithLegacyHeaderMerging(true))

// After: remove the option (legacy merging is gone)
jwe.Encrypt(payload, jwe.WithKey(alg, key))
```

### Recipe 13: JWT Validation Errors

v3 exposed sentinel validation errors as zero-argument functions (`jwt.TokenExpiredError()`, `jwt.InvalidIssuerError()`, etc.) returning a singleton `error`. v4 promotes them to struct types carrying the values used in the comparison (`Expiration`, `Now`, `Skew`, `IssuedAt`, `NotBefore`, etc.), which means the call-site idiom changes.

Rewrite `errors.Is` checks to pass a zero-value struct literal instead of a function call:

```go
// Before (v3)
if errors.Is(err, jwt.TokenExpiredError()) {
    // ...
}

// After (v4)
if errors.Is(err, jwt.TokenExpiredError{}) {
    // ...
}
```

To inspect the structured fields, use `errors.AsType[T]` (Go 1.26+):

```go
if expErr, ok := errors.AsType[jwt.TokenExpiredError](err); ok {
    log.Printf("token expired at %s (now=%s, skew=%s)", expErr.Expiration, expErr.Now, expErr.Skew)
}
```

The same function→struct rewrite applies to: `TokenExpiredError`, `TokenNotYetValidError`, `InvalidIssuedAtError`, `InvalidIssuerError`, `InvalidAudienceError`, `MissingRequiredClaimError`, `ValidationError` (was `ValidateError()`), `ParseError`, `ClaimNotFoundError`, and `ClaimAssignmentFailedError`.

## Patterns Requiring Manual Review

These changes cannot be mechanically transformed and need human judgment:

1. **Custom `Signer2`/`Verifier2` implementations**: If your implementation used `Algorithm()` for internal dispatch, you need to restructure. The algorithm is now passed to `RegisterSigner`/`RegisterVerifier` only.

2. **Complex cache configurations**: If you used `WithHttprcResourceOption`, `WithConstantInterval`, or other httprc-specific options with jwk.Cache, review the `jwkfetch` extension module's `RegisterOption` family for equivalents. Note that per-URL `WithHTTPClient` / `WithMaxFetchBodySize` overrides from the v3 jwkcache companion are not carried forward — in jwkfetch, HTTP transport and body-size cap are set once on `NewCache` via `WithHTTPClient` / `WithMaxBodySize` and apply uniformly to every registered URL.

3. **jku whitelist configuration**: Audit every `jws.WithVerifyAuto` / `jwt.WithVerifyAuto` call site. In v3 these accepted fetch options and prepended an implicit deny-all whitelist, so a caller who didn't pass `jwk.WithFetchWhitelist(...)` got rejected URLs. In v4, `WithVerifyAuto` takes only a `jwk.Fetcher` and jwx does not wrap it with any default-deny — the whitelist has to be configured on the fetcher itself at construction time. If your v3 code was of the form `jws.WithVerifyAuto(nil, jwk.WithFetchWhitelist(wl), jwk.WithHTTPClient(c))`, you must rewrite it as `jws.WithVerifyAuto(jwkfetch.NewClient(jwkfetch.WithWhitelist(wl), jwkfetch.WithHTTPClient(c)))` or the `jku` URL will be fetched with no policy. A `jwkfetch.Client` built with no `WithWhitelist` permits every URL, so a bare `jwkfetch.NewClient()` is dangerous for jku verification.

4. **`json.Number` usage**: If you relied on `json.Number` type preservation via `jwx.WithUseNumber(true)`, use `jwx.Settings(jwx.WithUseNumber(true))` instead. The API was renamed from `DecoderSettings` to `Settings` to match the sub-package convention.

5. **Code that catches specific error messages**: If you matched on error message strings from the crypto layer (e.g., during JWS signing), those errors may now occur earlier (at `WithKey()` time) due to algorithm-key validation.

6. **`Settings()` calls**: `jwt.Settings`, `jws.Settings`, `jwe.Settings`, `cert.Settings`, `jwx.Settings`, and `jwk.Settings` now return `error` instead of panicking (or silently accepting invalid state) on bad inputs. Call sites need to either check the returned error or explicitly discard it:

   ```go
   // Before (v3): invalid value panicked (or silently accepted)
   jws.Settings(jws.WithMaxSignatures(n))
   jwx.Settings(jwx.WithBase64Encoder(enc))

   // After (v4): check the error
   if err := jws.Settings(jws.WithMaxSignatures(n)); err != nil {
       return err
   }
   if err := jwx.Settings(jwx.WithBase64Encoder(enc)); err != nil {
       return err
   }
   ```

   Extension modules that install a backend in `init()` (e.g. `asmbase64`) must panic on error, matching the house style for `Register*` failures.

   `jwk.Settings` always returns `nil` today — its options (`WithMinRSAModulusBits`, `WithMinRSAPublicExponent`, `WithStrictKeyUsage`) have no validatable state, since `0` is a documented disable sentinel and `e=1` is a supported compatibility value. The `error` return exists for forward compatibility only.

7. **Filter + transform usage**: All filter types/constructors and the `transform` package moved out of core into `github.com/jwx-go/jwxfilter/v4`. If your code references `jwt.TokenFilter`, `jws.HeaderFilter`, `jwe.HeaderFilter`, `jwk.KeyFilter`, any `New*Filter` / `*StandardFilter()` / `openid.StandardClaimsFilter`, or anything in `transform`, add a dependency on the new companion and update imports:

   ```sh
   go get github.com/jwx-go/jwxfilter/v4
   ```

   ```go
   // Before
   import "github.com/lestrrat-go/jwx/v4/transform"
   filter := jwt.NewClaimNameFilter("sub", "iss")
   stripped, _ := filter.Filter(token)

   // After
   import "github.com/jwx-go/jwxfilter/v4/jwtfilter"
   filter := jwtfilter.ByName("sub", "iss")
   stripped, _ := filter.Filter(token)
   ```

   The four old filter interfaces (`jwt.TokenFilter`, `jws.HeaderFilter`, `jwe.HeaderFilter`, `jwk.KeyFilter`) collapse into one generic interface: `jwxfilter.Filter[T]`. The generic primitives in the old `transform` package (`FilterLogic`, `FilterLogicFunc`, `Filterable`, `NameBasedFilter`, `NewNameBasedFilter`, `Apply`, `Reject`) are no longer part of the public API — the companion keeps them unexported. Consumers that used them directly must migrate to the `<type>filter.ByName(...)` constructors.

## Build System Changes

1. Update `go.mod`:
   ```
   go 1.26.0
   require github.com/lestrrat-go/jwx/v4 v4.x.x
   ```

2. Set environment variable:
   ```bash
   export GOEXPERIMENT=jsonv2
   ```

3. Remove build tags from commands:
   ```bash
   # Before
   go test -tags=jwx_goccy,jwx_es256k ./...

   # After
   go test ./...
   ```

4. If using assembly base64 or ES256K, add the extension modules to `go.mod`:
   ```bash
   go get github.com/jwx-go/es256k/v4
   go get github.com/jwx-go/asmbase64/v4
   ```

## New Capabilities Worth Adopting

These are not breaking changes, but v3 callers moving to v4 may want to
pick them up when a natural opportunity presents itself.

### Streaming detached JWS for large payloads

v3 required the entire payload in memory for both `jws.Sign` and
`jws.Verify`, including the detached-payload variant
(`jws.WithDetachedPayload([]byte)`). v4 adds
`jws.WithDetachedPayloadReader(io.Reader)` for detached-payload
sign/verify against payloads that should not be materialized
(streaming file backups, multi-MB request bodies, etc.).

```go
// Signing a large file detached (v4)
f, _ := os.Open("payload.bin")
defer f.Close()
signed, err := jws.Sign(nil,
    jws.WithDetachedPayloadReader(f),
    jws.WithKey(jwa.RS256(), privkey),
)
```

Restrictions (enforced at sign/verify time):

- First argument to `jws.Sign` / `jws.Verify` must be `nil`; the reader
  supplies the payload bytes.
- Algorithms are HMAC / RSA / ECDSA only. EdDSA cannot stream (RFC 8032
  signs the full message, not a pre-computed digest) and custom algorithms
  registered via `jws.RegisterSigner` / `jws.RegisterVerifier` are
  rejected with a clear error pointing at `jws.WithDetachedPayload()`.
- On verify, multi-signature / JSON-serialization input is not accepted;
  `jws.WithKeySet`, `jws.WithKeyProvider`, and `jws.WithVerifyAuto` are
  refused. Pass a single `jws.WithKey`.
- The reader is consumed exactly once (no retry) and is accessed from
  the calling goroutine only — do not share a Reader across concurrent
  Sign/Verify calls unless it is itself goroutine-safe and
  independently positioned per call.
- Custom `jws.Base64Encoder` implementations must also satisfy
  `jws.Base64StreamEncoder` (adds `NewEncoder(io.Writer) io.WriteCloser`)
  to be usable on this path; the default encoder already does.

On verify success the first return value is a non-nil zero-length
`[]byte` — the verified payload was consumed by the Reader, not
materialized for you. Top-level `jws.Verify` godoc and the option
godoc each call this out.

See the runnable `Example_jws_sign_detached_reader` /
`Example_jws_verify_detached_reader` pair in the
[`jwx-go/examples`](https://github.com/jwx-go/examples) companion repo.
