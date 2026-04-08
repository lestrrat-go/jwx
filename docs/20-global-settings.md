# Global Settings

## Switching to a faster JSON library

By default, we use the standard library's `encoding/json` for all of our JSON needs.
However, if performance for parsing/serializing JSON is really important to you, you might want to enable [github.com/goccy/go-json](https://github.com/goccy/go-json) by enabling the `jwx_goccy` tag.

```shell
% go build -tags jwx_goccy ...
```

[github.com/goccy/go-json](https://github.com/goccy/go-json) is *disabled* by default because it uses some really advanced black magic, and I really do not feel like debugging it **IF** it breaks. Please note that that's a big "if".
As of github.com/goccy/go-json@v0.3.3 I haven't seen any problems, and I would say that it is mostly stable.

However, it is a dependency that you can go without, and I won't be of much help if it breaks -- therefore it is not the default.
If you know what you are doing, I highly recommend enabling this module -- all you need to do is to enable this tag.
Disable the tag if you feel like it's not worth the hassle.

And when you *do* enable [github.com/goccy/go-json](https://github.com/goccy/go-json), and you encounter some mysterious error, I also trust that you know to file an issue to [github.com/goccy/go-json](https://github.com/goccy/go-json) and **NOT** to this library.

## Using json.Number

If you want to parse numbers in the incoming JSON objects as json.Number
instead of floats, you can use the following call to globally affect the behavior of JSON parsing.

```go
func init() {
  jwx.DecoderSettings(jwx.WithUseNumber(true))
}
```

Do be aware that this has *global* effect. All code that calls in to `encoding/json`
within `jwx` *will* use your settings.

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


