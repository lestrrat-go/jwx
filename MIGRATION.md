# Migrating from jwx v3 to v4

This guide covers all breaking changes between `github.com/lestrrat-go/jwx/v3` and `github.com/lestrrat-go/jwx/v4`.

The [`jwxmigrate`](https://github.com/jwx-go/jwxmigrate) tool can apply mechanical fixes automatically and report issues that require manual review:

    go install github.com/jwx-go/jwxmigrate@latest

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
| `ReadFile(path, opts...)` | `ParseFS(fsys, path, opts...)` | All packages |
| `RegisterCustomField(name, obj)` | `RegisterCustomField[T](name)` | All packages |
| `jwk.RegisterProbeField(reflect.StructField{...})` | `jwk.RegisterProbeField[T](name, jsonKey)` | No `reflect` import needed |
| `jwk.Import(raw)` | `jwk.Import[T](raw)` | Generic return type |
| `jwk.ParseKey(data)` | `jwk.ParseKey[T](data)` | Generic return type |
| `jwk.NewCache(ctx, client)` | `jwkcache.NewCache(ctx, client)` | Extension module |
| `jws.Signer2` | `jws.Signer` | Interface renamed |
| `jws.Verifier2` | `jws.Verifier` | Interface renamed |
| `jws.RegisterSigner(alg, any)` | `jws.RegisterSigner(alg, Signer)` | Typed parameter |
| `jws.RegisterVerifier(alg, any)` | `jws.RegisterVerifier(alg, Verifier)` | Typed parameter |
| `jwx.DecoderSettings(...)` | _(removed)_ | json/v2 handles this |
| `-tags=jwx_goccy` | _(removed)_ | json/v2 is the only backend |
| `-tags=jwx_es256k` | `github.com/jwx-go/es256k/v4` | Extension module |
| `-tags=jwx_asmbase64` | `github.com/jwx-go/asmbase64/v4` | Extension module |
| `jwa.ES256K()` | `es256k.ES256K()` | `import "github.com/jwx-go/es256k/v4"` |
| `jwa.Ed448()` | `ed448.Ed448Curve()` | `import "github.com/jwx-go/ed448/v4"` |
| `jwa.EdDSAEd448()` | `ed448.EdDSAEd448()` | `import "github.com/jwx-go/ed448/v4"` |

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

```go
// Before
token, err := jwt.ReadFile("path/to/token.jwt")
set, err := jwk.ReadFile("path/to/keys.json")
msg, err := jws.ReadFile("path/to/message.jws")

// After
token, err := jwt.ParseFS(os.DirFS("."), "path/to/token.jwt")
set, err := jwk.ParseFS(os.DirFS("."), "path/to/keys.json")
msg, err := jws.ParseFS(os.DirFS("."), "path/to/message.jws")
```

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

### Recipe 6: JWK Caching

The caching subsystem moved to a separate module.

```go
// Before
import (
    "github.com/lestrrat-go/httprc/v3"
    "github.com/lestrrat-go/jwx/v3/jwk"
)

cache, err := jwk.NewCache(ctx, httprc.NewClient())
cache.Register(ctx, url, jwk.WithMinRefreshInterval(15*time.Minute))
set, err := cache.Lookup(ctx, url)

// After
import (
    "github.com/lestrrat-go/httprc/v3"
    "github.com/jwx-go/jwkcache/v4"
)

cache, err := jwkcache.NewCache(ctx, httprc.NewClient())
if err != nil {
    return err
}
if err := cache.Register(ctx, url); err != nil {
    return err
}
set, err := cache.Lookup(ctx, url)
```

### Recipe 7: Custom Field Registration

```go
// Before
jwt.RegisterCustomField("my-field", time.Time{})
jwk.RegisterCustomField("x-custom", "")

// After
jwt.RegisterCustomField[time.Time]("my-field")
jwk.RegisterCustomField[string]("x-custom")
```

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
import "github.com/jwx-go/ed448/v4"   // ed448.EdDSAEd448(), ed448.Ed448Curve()
import _ "github.com/jwx-go/asmbase64/v4" // registration only
```

### Recipe 10: Custom Key Importer

```go
// Before
jwk.RegisterKeyImporter(&myKeyType{}, jwk.KeyImportFunc(func(raw any) (jwk.Key, error) {
    src, ok := raw.(*myKeyType)
    if !ok {
        return nil, fmt.Errorf("expected *myKeyType, got %T", raw)
    }
    // ... convert
}))

// After
jwk.RegisterKeyImporter(func(src *myKeyType) (jwk.Key, error) {
    // ... convert — type parameter inferred, no assertion needed
})
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

## Patterns Requiring Manual Review

These changes cannot be mechanically transformed and need human judgment:

1. **Custom `Signer2`/`Verifier2` implementations**: If your implementation used `Algorithm()` for internal dispatch, you need to restructure. The algorithm is now passed to `RegisterSigner`/`RegisterVerifier` only.

2. **Complex cache configurations**: If you used `WithHttprcResourceOption`, `WithConstantInterval`, or other httprc-specific options with jwk.Cache, review the jwkcache extension module's API for equivalents.

3. **`json.Number` usage**: If you stored custom numeric fields and relied on `json.Number` type preservation via `jwx.WithUseNumber(true)`, your code needs to handle `float64` instead, or use a custom decoder.

4. **Code that catches specific error messages**: If you matched on error message strings from the crypto layer (e.g., during JWS signing), those errors may now occur earlier (at `WithKey()` time) due to algorithm-key validation.

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
