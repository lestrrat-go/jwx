# Generics Adoption

## Motivation

v3 used `any`/`interface{}` extensively for key import/export registration, field accessors, and JSON custom field decoders. This required runtime type assertions and `reflect` calls. Go generics eliminate much of this boilerplate while providing compile-time type safety.

## Changes

### Generic KeyImporter registration

**v3:**
```go
jwk.RegisterKeyImporter(&rsa.PrivateKey{}, jwk.KeyImportFunc(myFunc))
// myFunc must accept `any` and type-switch internally
func myFunc(src any) (jwk.Key, error) {
    raw, ok := src.(*rsa.PrivateKey)
    if !ok { return nil, err }
    ...
}
```

**v4:**
```go
jwk.RegisterKeyImporter[*rsa.PrivateKey](
    jwk.KeyImportFunc[*rsa.PrivateKey](myFunc),
)
// myFunc accepts the concrete type — the adapter type-asserts for it
func myFunc(src *rsa.PrivateKey) (jwk.Key, error) {
    ...
}
```

Implementation: `RegisterKeyImporter[T any](ki KeyImporter) error` uses `reflect.TypeFor[T]()` to derive the map key at registration time. The runtime dispatch in `Import()` still uses `reflect.TypeOf(raw)` — this is unavoidable since the input type is only known at call time. The type parameter `T` is solely a dispatch-key declaration; it does not appear in the function signature.

`KeyImportFunc[T any]` is the typed-function adapter: its `Import` method type-asserts the raw `any` argument to `T` and invokes the underlying typed function. Callers with a full `KeyImporter` implementation pass it directly without the adapter.

Earlier v4 iterations had `RegisterKeyImporter[T](fn func(T) (Key, error))` — accepting a typed function rather than a `KeyImporter`, with `KeyImportFunc` exposed as a separate untyped adapter that was never reachable from registration. The current shape restores the interface as the canonical registration value and makes `KeyImportFunc[T]` generic, so a single name covers the typed-function convenience.

### Type-safe generic accessors

**v3:**
```go
var issuer string
err := token.Get(jwt.IssuerKey, &issuer)
```

**v4:**
```go
issuer, err := jwt.Get[string](token, jwt.IssuerKey)
custom, err := jwt.Get[MyType](token, "my-custom-claim")
```

Added as free functions in each package: `jwt.Get[T]`, `jwk.Get[T]`, `jws.Get[T]`, `jwe.Get[T]`. The underlying `Get(string, any) error` method remains on the interface.

### Generic TypedDecoder for custom fields

`internal/json/registry.go` added `TypedDecoder[T any]` which replaces `objectTypeDecoder`'s `reflect.New(typ)` with a simple `new(T)`. Registration via `RegisterTyped[T](registry, name)`.

### Generic keyconv helper

`internal/keyconv` added `convertPrivateKey[T any](dst, src any) error` which handles the common pattern of JWK export + value/pointer type switch + `blackmagic.AssignIfCompatible`. `RSAPrivateKey`, `ECDSAPrivateKey`, and `Ed25519PrivateKey` are now one-line delegations.

## Migration guide (v3 → v4)

```go
// v3: register custom key importer
jwk.RegisterKeyImporter(&myKey{}, jwk.KeyImportFunc(func(src any) (jwk.Key, error) {
    k, ok := src.(*myKey)
    if !ok { return nil, fmt.Errorf("wrong type") }
    return doImport(k)
}))

// v4: type parameter declares the dispatch key; pass a KeyImporter
// (KeyImportFunc adapts a typed function).
jwk.RegisterKeyImporter[*myKey](
    jwk.KeyImportFunc[*myKey](func(k *myKey) (jwk.Key, error) {
        return doImport(k)
    }),
)
```

```go
// v3: field access
var kid string
err := key.Get(jwk.KeyIDKey, &kid)

// v4: generic accessor
kid, err := jwk.Get[string](key, jwk.KeyIDKey)
```
