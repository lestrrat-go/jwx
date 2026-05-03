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
jwk.RegisterKeyImporter(jwk.KeyImportFunc[*rsa.PrivateKey](myFunc))
// myFunc accepts the concrete type. The outer T is inferred from the
// adapter's typed Import method.
func myFunc(src *rsa.PrivateKey) (jwk.Key, error) {
    ...
}
```

Implementation: `KeyImporter[T any]` is a generic interface whose `Import(raw T) (Key, error)` method is itself typed; `KeyImportFunc[T any]` is a `func(T) (Key, error)` that satisfies it. `RegisterKeyImporter[T any](ki KeyImporter[T]) error` uses `reflect.TypeFor[T]()` to derive the map key at registration time and stores a closure that re-types `any` → T at dispatch. The runtime lookup in `Import()` still keys by `reflect.TypeOf(raw)`.

The earlier v4.0.0 release shipped `RegisterKeyImporter[T](fn func(T) (Key, error))` — accepting a typed function rather than a `KeyImporter`, with the public `KeyImporter` interface and `KeyImportFunc` adapter exposed but never reachable from registration. The current shape restores the interface as the canonical registration value, makes the interface generic so type-parameter inference covers the registration call, and makes `KeyImportFunc[T]` a generic typed-function adapter that satisfies it.

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

// v4: pass a KeyImporter[T]; T inferred from the adapter's typed Import.
jwk.RegisterKeyImporter(jwk.KeyImportFunc[*myKey](func(k *myKey) (jwk.Key, error) {
    return doImport(k)
}))
```

```go
// v3: field access
var kid string
err := key.Get(jwk.KeyIDKey, &kid)

// v4: generic accessor
kid, err := jwk.Get[string](key, jwk.KeyIDKey)
```
