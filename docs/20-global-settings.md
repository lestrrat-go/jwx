# Global Settings

## Using json.Number

If you want to parse numbers in the incoming JSON objects as json.Number
instead of floats, you can use the following call to globally affect the behavior of JSON parsing.

```go
func init() {
  jwx.Settings(jwx.WithUseNumber(true))
}
```

Do be aware that this has *global* effect. All code that calls in to `encoding/json`
within `jwx` *will* use your settings.

**Apply this once at program startup** — from `func init()` or early in `main()`,
before any goroutine begins parsing JWx payloads. The underlying flag is
read atomically, so toggling it at runtime will not race, but any decoders
already running (or started after the flip) will produce a mix of `float64`
and `json.Number` values in concurrently-decoded custom fields, and callers
that type-assert on those values will break non-deterministically. There is
no per-call override.

## Decode private fields to objects

Packages within `github.com/lestrrat-go/jwx/v4` parses known fields into pre-defined types,
but for everything else (usually called private fields/headers/claims) are decoded into
whatever `"encoding/json".Unmarshal` deems appropriate.

For example, JSON objects are converted to `map[string]interface{}`, JSON arrays into
`[]interface{}`, and so on.

Sometimes you know beforehand that it makes sense for certain fields to be decoded into
proper objects instead of generic maps or arrays. When you encounter this, you can use
the `RegisterCustomField()` function in each of `jwe`, `jwk`, `jws`, and `jwt` packages.

```go
func init() {
  jwt.RegisterCustomField[mypkg.FooBar](`x-foo-bar`)
}
```

This tells the decoder that when it encounters a JWT token with the field named
`"x-foo-bar"`, it should be decoded to an instance of `mypkg.FooBar`. Then you can
access this value by using `Get()`

```go
v, err := jwt.Get[mypkg.FooBar](token, `x-foo-bar`)
```

If you need more control over the decoding process, use `RegisterCustomDecoder`:

```go
func init() {
  jwt.RegisterCustomDecoder(`x-foo-bar`, jwt.CustomDecodeFunc[mypkg.FooBar](func(data []byte) (mypkg.FooBar, error) {
    // custom decoding logic
  }))
}
```

Do be aware that this has *global* effect. In the above example, all JWT tokens containing
the `"x-foo-bar"` key will decode in the same way. If you need this behavior from
`jwe`, `jwk`, or `jws` packages, you need to do the same thing for each package.


