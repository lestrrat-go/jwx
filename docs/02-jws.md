# Working with JWS

In this document we describe how to work with JWS using [`github.com/lestrrat-go/jwx/v4/jws`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws)

* [Parsing](#parsing)
  * [Parse a JWS message stored in memory](#parse-a-jws-message-stored-in-memory)
  * [Parse a JWS message stored in a file](#parse-a-jws-message-stored-in-a-file)
  * [Parse a JWS message and access JWS headers](#parse-a-jws-message-and-access-jws-headers)
* [Signing](#signing)
  * [Generating a JWS message in compact serialization format](#generating-a-jws-message-in-compact-serialization-format)
  * [Generating a JWS message in JSON serialization format](#generating-a-jws-message-in-json-serialization-format)
  * [Generating a JWS message with detached payload](#generating-a-jws-message-with-detached-payload)
  * [Using cloud KMS services](#using-cloud-kms-services)
  * [Including arbitrary headers](#including-arbitrary-headers)
* [Verifying](#verifying)
  * [Verification using a single key](#verification-using-a-single-key)
  * [Verification using a JWKS](#verification-using-a-jwks)
  * [Verification using a detached payload](#verification-using-a-detached-payload)
  * [Verification using `jku`](#verification-using-jku)
* [Using a custom signing/verification algorithm](#using-a-custom-signingverification-algorithm)
* [Using a custom base64 encoder](#using-a-custom-base64-encoder)
* [Filtering JWS headers](#filtering-jws-headers)

# Parsing

Parsing a JWS message means taking either a JWS message serialized in JSON or Compact form
and loading it into a `jws.Message` object. No verification is performed, and therefore
you cannot "trust" the contents in the same way that a verified message could be trusted.

Also, be aware that a `jws.Message` is not meant to be used for either signing or
verification. It is only provided such that it can be inspected -- there is no way
to sign or verify using a parsed `jws.Message`. To do this, you would need to use
`jws.Sign()` or `jws.Message()`.

## Parse a JWS message stored in memory

You can parse a JWS message in memory stored as `[]byte` into a [`jws.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws#Message) object. In this mode, there is no verification performed.

<!-- INCLUDE(examples/jws_parse_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_parse() {
  const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo`

  msg, err := jws.Parse([]byte(src))
  if err != nil {
    fmt.Printf("failed to parse JWS message: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(msg)
  // OUTPUT:
  // {"payload":"TG9yZW0gaXBzdW0","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo"}
}
```
source: [examples/jws_parse_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_parse_example_test.go)
<!-- END INCLUDE -->

## Parse a JWS message stored in a file

To parse a JWS stored in a file, use [`jws.ParseFS()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws#ParseFS). [`jws.ParseFS()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws#ParseFS) accepts the same options as [`jws.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws#Parse).

<!-- INCLUDE(examples/jws_parsefs_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"
  "path/filepath"

  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_ParseFS() {
  const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo`
  f, err := os.CreateTemp(``, `jws_parsefs-*.jws`)
  if err != nil {
    fmt.Printf("failed to create temporary file: %s\n", err)
    return
  }
  defer os.Remove(f.Name())

  fmt.Fprint(f, src)
  f.Close()

  msg, err := jws.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()))
  if err != nil {
    fmt.Printf("failed to parse JWS message: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(msg)

  // OUTPUT:
  // {"payload":"TG9yZW0gaXBzdW0","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo"}
}
```
source: [examples/jws_parsefs_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_parsefs_example_test.go)
<!-- END INCLUDE -->

## Parse a JWS message and access JWS headers

Note: If you are considering using JWS header fields to decide on which key to use for verification, consider [using a `jwt.KeyProvider`](./01-jwt.md#parse-and-verify-a-jwt-using-arbitrary-keys).

While a lot of documentation in the wild treats as if a JWT message encoded in base64 is... a JWT message, in truth it is a JWT message enveloped in a JWS message. Therefore, in order to access the JWS headers of a JWT message you will need to work with a `jws.Message` object, which you can obtain from parsing the JWS payload. You will need to understand [the structure of a generic JWS message](https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1).

Below sample code extracts the `kid` field of a single-signature JWS message:

<!-- INCLUDE(examples/jws_use_jws_header_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jws_use_jws_header() {
  key, err := jwk.Import([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf(`failed to create new symmetric key: %s`, err)
    return
  }
  key.Set(jws.KeyIDKey, `secret-key`)

  tok, err := jwt.NewBuilder().
    Issuer(`github.com/lestrrat-go/jwx`).
    Build()
  if err != nil {
    fmt.Printf(`failed to build token: %s`, err)
    return
  }

  signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
  if err != nil {
    fmt.Printf(`failed to sign token: %s`, err)
    return
  }

  msg, err := jws.Parse(signed)
  if err != nil {
    fmt.Printf(`failed to parse serialized JWT: %s`, err)
    return
  }

  // While JWT enveloped with JWS in compact format only has 1 signature,
  // a generic JWS message may have multiple signatures. Therefore, we
  // need to access the first element
  kid, ok := msg.Signatures()[0].ProtectedHeaders().KeyID()
  if !ok {
    fmt.Printf("failed to get key ID from protected headers")
    return
  }
  fmt.Printf("%q\n", kid)
  // OUTPUT:
  // "secret-key"
}
```
source: [examples/jws_use_jws_header_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_use_jws_header_example_test.go)
<!-- END INCLUDE -->

# Signing

## Generating a JWS message in compact serialization format

To sign an arbitrary payload as a JWS message in compact serialization format, use `jwt.Sign()`.

Note that this would be [slightly different if you are signing JWTs](01-jwt.md#serialize-using-jws), as you would be
using functions from the `jwt` package instead of `jws`.

<!-- INCLUDE(examples/jws_sign_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_sign() {
  key, err := jwk.Import([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create key: %s\n", err)
    return
  }

  buf, err := jws.Sign([]byte("Lorem ipsum"), jws.WithKey(jwa.HS256(), key))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", buf)
  // OUTPUT:
  // eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.EjVtju0uXjSz6QevNgAqN1ESd9aNCP7-tJLifkQ0_C0
}
```
source: [examples/jws_sign_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_sign_example_test.go)
<!-- END INCLUDE -->

## Generating a JWS message in JSON serialization format

Generally the only time you need to use a JSON serialization format is when you have to generate multiple signatures for a given payload using multiple signing algorithms and keys.

When this need arises, use the [`jws.Sign()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws#Sign) function with the `jws.WithJSON()` option and multiple `jws.WithKey()` options:

<!-- INCLUDE(examples/jws_sign_json_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_sign_json() {
  var keys []jwk.Key

  for i := 0; i < 3; i++ {
    key, err := jwk.Import([]byte(fmt.Sprintf(`abracadabra-%d`, i)))
    if err != nil {
      fmt.Printf("failed to create key: %s\n", err)
      return
    }
    keys = append(keys, key)
  }

  options := []jws.SignOption{jws.WithJSON()}
  for _, key := range keys {
    options = append(options, jws.WithKey(jwa.HS256(), key))
  }

  buf, err := jws.Sign([]byte("Lorem ipsum"), options...)
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", buf)
  // OUTPUT:
  // {"payload":"TG9yZW0gaXBzdW0","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"bCQtU2y4PEnG78dUN-tXea8YEwhBAzLX7ZEYlRVtX_g"},{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"0ovW79M_bbaRDBrBLaNKN7rgJeXaSRAnu5rhAuRXBR4"},{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"ZkUzwlK5E6LFKsYEIyUvskOKLMDxE0MvvkvNrwINNWE"}]}
}
```
source: [examples/jws_sign_json_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_sign_json_example_test.go)
<!-- END INCLUDE -->

## Generating a JWS message with detached payload

JWS messages can be constructed with a detached payload. Use the `jws.WithDetachedPayload()` option to
create a JWS message with the message detached from the result.

<!-- INCLUDE(examples/jws_sign_detached_payload_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_sign_detached_payload() {
  payload := `$.02`

  key, err := jwk.Import([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create symmetric key: %s\n", err)
    return
  }

  // If you plan to transmit your payload without base64-encoding (RFC 7797),
  // it's best to set `b64: false` so libraries can act accordingly (e.g. the
  // popular NodeJS `jose` library requires it set to false in order to verify
  // a plaintext payload.
  hdrs := jws.NewHeaders()
  hdrs.Set("b64", false)
  hdrs.Set("crit", []string{"b64"})

  serialized, err := jws.Sign(nil, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)), jws.WithDetachedPayload([]byte(payload)))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }

  fmt.Printf("%s\n", serialized)
  // OUTPUT:
  // eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..lnRw_MSpQjARa5LWqPcu8Qls9p3wYGrC6tz4-nr0rkA
}
```
source: [examples/jws_sign_detached_payload_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_sign_detached_payload_example_test.go)
<!-- END INCLUDE -->

## Including arbitrary headers

By default, only some header fields are included in the result from `jws.Sign()`.
If you want to include more header fields in the resulting JWS, you will have to provide them via the `jws.WithProtectedHeaders()` option.

While `jws.WithPublicHeaders()` exists to keep API symmetric and complete, for most
cases you only want to use `jws.WithProtectedHeaders()`

<!-- INCLUDE(examples/jws_sign_with_headers_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_sign_with_headers() {
  key, err := jwk.Import([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create key: %s\n", err)
    return
  }

  hdrs := jws.NewHeaders()
  hdrs.Set(`x-example`, true)
  buf, err := jws.Sign([]byte("Lorem ipsum"), jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", buf)
  // OUTPUT:
  // eyJhbGciOiJIUzI1NiIsIngtZXhhbXBsZSI6dHJ1ZX0.TG9yZW0gaXBzdW0.9nIX0hN7u1b97UcjmrVvd5y1ubkQp_1gz1V3Mkkcm14
}
```
source: [examples/jws_sign_with_headers_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_sign_with_headers_example_test.go)
<!-- END INCLUDE -->

## Using cloud KMS services

If you want to use cloud KMSes such as AWS KMS to sign and verify payloads, look for an object that implements
`crypto.Signer`. There are some [implementations written for this module](https://github.com/jwx-go/crypto-signer). NOTE: THESE WERE WRITTEN FOR OLDER RELEASES. PLEASE SEND PRs IF YOU WANT THEM UPDATED.

Event if you cannot find an implementation that you are looking for in the above repository, any other implementation that implements `crypto.Signer` should work.

# Verifying

## Verification using a single key

To verify a JWS message using a single key, use `jws.Verify()` with the `jws.WithKey()` option.
It will automatically do the right thing whether it's serialized in compact form or JSON form.

The `alg` must be explicitly specified. See "[Why don't you automatically infer the algorithm for `jws.Verify`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)"

<!-- INCLUDE(examples/jws_verify_with_key_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_verify_with_key() {
  const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.EjVtju0uXjSz6QevNgAqN1ESd9aNCP7-tJLifkQ0_C0`

  key, err := jwk.Import([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create key: %s\n", err)
    return
  }

  buf, err := jws.Verify([]byte(src), jws.WithKey(jwa.HS256(), key))
  if err != nil {
    fmt.Printf("failed to verify payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", buf)
  // OUTPUT:
  // Lorem ipsum
}
```
source: [examples/jws_verify_with_key_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_verify_with_key_example_test.go)
<!-- END INCLUDE -->

## Verification using a JWKS

To verify a payload using JWKS, by default you will need your payload and JWKS to have matching `kid` and `alg` fields.

First the `alg` field's requirement is the same for using a single key. But you could, at a possible cost of trying multiple algorithms, let this module infer the algorithm to use by using the `jws.InferAlgorithmFromKey(true)` sub-option to `jws.WithKeySet()` (or `jwt.WithKeySet()`) See the example below for details.

(ref: "[Why don't you automatically infer the algorithm for `jws.Verify`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)").

And second, the `kid` field by default must match between the JWS signature and the key in JWKS. This can be explicitly disabled by specifying the `jws.WithRequireKid(false)` suboption when using the `jws.WithKeySet()` option (i.e.: `jws.WithKeySet(keyset, jws.WithRequireKid(false))`).

For more discussion on why/how `alg`/`kid` values work, please read the [relevant section in the JWT documentation](01-jwt.md#parse-and-verify-a-jwt-with-a-key-set-matching-kid).

<!-- INCLUDE(examples/jws_verify_with_keyset_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/internal/jwxtest"
  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_verify_with_jwk_set() {
  // Setup payload, private key, and signed payload first...
  const payload = "Lorem ipsum"
  privkey, err := jwxtest.GenerateRsaJwk()
  if err != nil {
    fmt.Printf("failed to create private key: %s\n", err)
    return
  }
  const keyID = "correct-key"
  _ = privkey.Set(jwk.KeyIDKey, keyID)

  // Create a JWK Set
  set := jwk.NewSet()
  // Add some bogus keys
  k1, _ := jwk.Import([]byte("abracadabra"))
  _ = set.AddKey(k1)
  _ = k1.Set(jwk.KeyIDKey, "key-01")

  k2, _ := jwk.Import([]byte("opensesame"))
  _ = set.AddKey(k2)
  _ = k1.Set(jwk.KeyIDKey, "key-02")

  // AddKey the real thing. Note that k3 already contains the Key ID because
  // jwk.PublicKeyOf(jwk) automatically sets the Key ID if it is present in the private key.
  k3, _ := jwk.PublicKeyOf(privkey)
  _ = set.AddKey(k3)

  // Up to this point, you probably will replace with a simple jwk.Fetch()
  // or similar to obtain the JWKS

  // Sign with a key that has a Key ID. This forces jws.Sign() to include its
  // key ID in the JWS header.
  signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), privkey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }

  // Now let's try to verify the signed payload under various conditions

  { // No Key ID, nor algorithm present in the key}
    k3.Remove(jwk.KeyIDKey) // Remove Key ID so that it won't work

    // This fails, because it's going to try to lookup a key to use using the Key ID,
    // but it can't be found
    if _, err := jws.Verify(signed, jws.WithKeySet(set)); err == nil {
      fmt.Printf("Able to verify using jwk.Set, when it shouldn't: %s", err)
      return
    }

    // Now let's add a WithRequireKid(false). This will STILL fail, because the key
    // matching the key ID doesn't have an algorithm value set.
    if _, err := jws.Verify(signed, jws.WithKeySet(set, jws.WithRequireKid(false))); err == nil {
      fmt.Printf("Able to verify using jwk.Set, when it shouldn't: %s", err)
      return
    }

    // This works, because we're telling it to infer the algorithm by the
    // key type.
    if _, err := jws.Verify(signed, jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true), jws.WithRequireKid(false))); err != nil {
      fmt.Printf("Failed to verify using jwk.Set: %s", err)
      return
    }
  }

  { // Key ID present, but no algorithm
    k3.Set(jwk.KeyIDKey, keyID) // Add Key ID back

    // This does not work because the while the library can find
    // a key matching the key ID, it doesn't know what algorithm to use
    if _, err := jws.Verify(signed, jws.WithKeySet(set)); err == nil {
      fmt.Printf("Able to verify using jwk.Set, when it shouldn't: %s", err)
      return
    }

    // This works, because the library can find a key matching the key ID,
    // and it can infer the algorithm from the key type
    if _, err := jws.Verify(signed, jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true))); err != nil {
      fmt.Printf("Failed to verify using jwk.Set: %s", err)
      return
    }
  }

  { // both Key ID and algorithm present
    // And finally, the "cleanest" way.
    k3.Set(jwk.AlgorithmKey, jwa.RS256()) // Set algorithm

    if _, err := jws.Verify(signed, jws.WithKeySet(set)); err != nil {
      fmt.Printf("Failed to verify using jwk.Set: %s", err)
      return
    }
  }

  // If you just can't do this (e.g. because your token doesn't have a Key ID),
  // then you're better off using the single-key option jws.WithKey() (or the jwt.WithKey() option)

  // OUTPUT:
}
```
source: [examples/jws_verify_with_keyset_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_verify_with_keyset_example_test.go)
<!-- END INCLUDE -->

## Verification using a detached payload

To verify a JWS message with detached payload, use the `jws.WithDetachedPayload()` option:

<!-- INCLUDE(examples/jws_verify_detached_payload_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_verify_detached_payload() {
  serialized := `eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..lnRw_MSpQjARa5LWqPcu8Qls9p3wYGrC6tz4-nr0rkA`
  payload := `$.02`

  key, err := jwk.Import([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create symmetric key: %s\n", err)
    return
  }

  verified, err := jws.Verify([]byte(serialized), jws.WithKey(jwa.HS256(), key), jws.WithDetachedPayload([]byte(payload)))
  if err != nil {
    fmt.Printf("failed to verify payload: %s\n", err)
    return
  }

  fmt.Printf("%s\n", verified)
  // OUTPUT:
  // $.02
}
```
source: [examples/jws_verify_detached_payload_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_verify_detached_payload_example_test.go)
<!-- END INCLUDE -->

## Verification using `jku`

Regular calls to `jws.Verify()` does not respect the JWK Set referenced in the `jku` field. In order to
verify the payload using the `jku` field, you must use the `jws.VerifyAuto()` function.

```go
wl := ... // Create an appropriate whitelist
payload, _ := jws.VerifyAuto(buf, jws.WithFetchWhitelist(wl))
```

This will tell `jws` to verify the given buffer using the JWK Set presented at the URL specified in
the `jku` field. If the buffer is a JSON message, then this is done for each of the signature in
the `signatures` array.

The URL in the `jku` field must have the `https` scheme, and the key ID in the JWK Set must
match the key ID present in the JWS message.

Because this operation will result in your program accessing remote resources, the default behavior
is to NOT allow any URLs. You must specify a whitelist

```go
wl := jwk.NewMapWhitelist().
  Add(`https://white-listed-address`)

payload, _ := jws.VerifyAuto(buf, jws.WithFetchWhitelist(wl))
```

If you want to allow any URLs to be accessible, use the `jwk.InsecureWhitelist`.

```go
wl := jwk.InsecureWhitelist{}
payload, _ := jws.VerifyAuto(buf, jws.WithFetchWhitelist(wl))
```

If you must configure the HTTP Client in a special way, use the `jws.WithHTTPClient()` option:

```go
client := &http.Client{ ... }
payload, _ := jws.VerifyAuto(buf, jws.WithHTTPClient(client))
```

# Using a custom signing/verification algorithm

Sometimes we do not offer a particular algorithm out of the box, but you have an implementation for it.

In such scenarios, you can use the [`jws.RegisterSigner()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws#RegisterSigner) and [`jws.RegisterVerifier()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws#RegisterVerifier) functions to
generate your own verifier instance. 

<!-- INCLUDE(examples/jws_custom_signer_verifier_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "fmt"

  "github.com/cloudflare/circl/sign/ed25519"
  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_custom_signer_verifier() {
  if err := jws.RegisterSigner(jwa.EdDSA(), CirclEdDSASigner{}); err != nil {
    fmt.Printf(`failed to register signer: %s`, err)
    return
  }

  if err := jws.RegisterVerifier(jwa.EdDSA(), CirclEdDSAVerifier{}); err != nil {
    fmt.Printf(`failed to register verifier: %s`, err)
    return
  }
  pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
  if err != nil {
    fmt.Printf(`failed to generate keys: %s`, err)
    return
  }

  const payload = "Lorem Ipsum"
  signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.EdDSA(), privkey))
  if err != nil {
    fmt.Printf(`failed to generate signed message: %s`, err)
    return
  }

  verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSA(), pubkey))
  if err != nil {
    fmt.Printf(`failed to verify signed message: %s`, err)
    return
  }

  if string(verified) != payload {
    fmt.Printf(`got invalid payload: %s`, verified)
    return
  }

  // OUTPUT:
  // Custom signer called
  // Custom verifier called
}

type CirclEdDSASigner struct{}

// Sign implements the jws.Signer interface for Circl's EdDSA signer.
//
// Signer is a relatively low-level API. It receives multiple parameters because of this.
//
// One thing you should do in your signer is to check the type of the key passed in.
// We have no way of constricting the type of key that is passed in without knowing
// the implementation details of your custom signer, and thus we cannot guarantee that
// users will pass in the correct type of key.
//
// Those implementing the jws.Signer interface could construct the buffer to be signed
// themselves and generate the signature, but it is often easier to use the jwsbb.Sign
// function, which takes care of the constructiion. In this example, we would like to
// tell jwsbb.Sign to construct the buffer and generate the signature using ed25519.Sign,
// but since the function signatures do not match, we are providing an adapter
// that implements the dsig.Signer interface.
//
// If you need to construct the buffer yourself, you can do so by using the
// jwsbb.SignBuffer() function in combination with the jwsbb.SignRaw() function.
func (CirclEdDSASigner) Sign(key any, payload []byte) ([]byte, error) {
  fmt.Println("Custom signer called")
  privkey, ok := key.(ed25519.PrivateKey)
  if !ok {
    return nil, fmt.Errorf(`jws.CirclEdDSASigner: invalid key type %T. ed25519.PrivateKey is required`, key)
  }
  return ed25519.Sign(privkey, payload), nil
}

type CirclEdDSAVerifier struct{}

// Verify implements the jws.Verifier interface for Circl's EdDSA verifier.
//
// See the comments for CirclEdDSASigner.Sign for more information on what this function does.
func (CirclEdDSAVerifier) Verify(key any, payload, signature []byte) error {
  fmt.Println("Custom verifier called")
  pubkey, ok := key.(ed25519.PublicKey)
  if !ok {
    return fmt.Errorf(`jws.CirclECDSASignerVerifier: invalid key type %T. ed25519.PublicKey is required`, key)
  }

  if ed25519.Verify(pubkey, payload, signature) {
    return nil
  }
  return fmt.Errorf(`failed to verify EdDSA signature`)
}
```
source: [examples/jws_custom_signer_verifier_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_custom_signer_verifier_example_test.go)
<!-- END INCLUDE -->

## Enabling Ed448

Ed448 support is not included by default. Import the `ed448` module for side effects to enable it:

<!-- INCLUDE(examples/jws_ed448_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/cloudflare/circl/sign/ed448"
  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jws"

  // Importing jwx-circl-ed448 for its side effects registers Ed448
  // with jwa, jws, and jwk, making it fully available for JWS operations.
  _ "github.com/lestrrat-go/jwx-circl-ed448"
)

func Example_jws_sign_ed448() {
  pub, priv, err := ed448.GenerateKey(nil)
  if err != nil {
    fmt.Printf("failed to generate key: %s\n", err)
    return
  }

  payload := []byte("Hello, Ed448!")

  signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd448(), priv))
  if err != nil {
    fmt.Printf("failed to sign: %s\n", err)
    return
  }

  verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd448(), pub))
  if err != nil {
    fmt.Printf("failed to verify: %s\n", err)
    return
  }

  fmt.Printf("%s\n", verified)
  // OUTPUT:
  // Hello, Ed448!
}
```
source: [examples/jws_ed448_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_ed448_example_test.go)
<!-- END INCLUDE -->

# Using a custom base64 encoder

Per specification JWS should be using URL base64 encoding with no padding when generating (and by nature of the process when verifying as well) signatures. However, some systems do not necessarily adhere to the standards ([there have been reports that AWS ALB is one such system, generating User Claims JWT with padding](https://github.com/lestrrat-go/jwx/discussions/1324))

In these situations, you will need to specify the base64 encoder to your `jws.Sign` and `jws.Verify` calls.
Please note that this feature is available on v3 onwards only.

<!-- INCLUDE(examples/jws_sign_with_custom_base64_example_test.go) -->
```go
package examples_test

import (
  "bytes"
  "encoding/base64"
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_sign_with_custom_base64() {
  const payload = "Lorem ipsum"
  const symmetricKey = "0123456789abcdef0123456789abcdef"

  signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.HS256(), []byte(symmetricKey)), jws.WithBase64Encoder(base64.URLEncoding))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
  }

  fmt.Println(string(signed))

  // This should fail because we're using a different base64 encoder
  if _, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), []byte(symmetricKey))); err == nil {
    fmt.Printf("verification should have failed, but succeeded\n")
    return
  }

  verified, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), []byte(symmetricKey)), jws.WithBase64Encoder(base64.URLEncoding))
  if err != nil {
    fmt.Printf("failed to verify payload: %s\n", err)
    return
  }

  if !bytes.Equal([]byte(payload), verified) {
    fmt.Printf("verified content do not match: %s\n", err)
    return
  }
  // OUTPUT:
  // eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0=.DahnsWNiVXmt23d2nUx_ePAZLy2nodC-Oh0bIB88cck=
}
```
source: [examples/jws_sign_with_custom_base64_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_sign_with_custom_base64_example_test.go)
<!-- END INCLUDE -->

You can use these option for `jwt.Sign` and `jwt.Parse` as well. See the [JWT docs for an example](./01-jwt.md#using-a-custom-base64-encoder).

# Filtering JWS headers

**Important:** The filtering functionality described in this section operates on JWS headers only, not on the JWS message itself, nor can you filter or modify the payload of a JWS message directly using these filters.

The JWS library provides filtering capabilities that allow you to selectively include or exclude specific header fields from JWS headers. This is particularly useful when you need to:

- Remove sensitive information from headers before logging or transmission
- Extract only specific header fields for processing
- Separate standard JWS headers from custom application-specific headers
- Create environment-specific header configurations

The filtering operates on parsed JWS messages and their headers, allowing you to create new header objects with only the fields you need.

## Basic header filtering

You can filter JWS headers using the [`jws.HeaderNameFilter`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws#HeaderNameFilter):

<!-- INCLUDE(examples/jws_filter_basic_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_header_filter_basic() {
  // Create a key for signing
  key, err := jwk.Import([]byte(`my-secret-key`))
  if err != nil {
    fmt.Printf("failed to create key: %s\n", err)
    return
  }

  // Create headers with both standard and custom fields
  headers := jws.NewHeaders()
  headers.Set(jws.AlgorithmKey, jwa.HS256())
  headers.Set(jws.KeyIDKey, "key-2024")
  headers.Set(jws.TypeKey, "JWT")
  headers.Set("custom-claim", "important-data")
  headers.Set("app-version", "v1.2.3")
  headers.Set("environment", "production")

  // Sign with custom headers
  payload := []byte(`{"user": "alice", "role": "admin"}`)
  signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(headers)))
  if err != nil {
    fmt.Printf("failed to sign: %s\n", err)
    return
  }

  // Parse the signed message to access headers
  msg, err := jws.Parse(signed)
  if err != nil {
    fmt.Printf("failed to parse: %s\n", err)
    return
  }

  originalHeaders := msg.Signatures()[0].ProtectedHeaders()

  // Filter 1: Extract only custom fields using HeaderNameFilter
  customFilter := jws.NewHeaderNameFilter("custom-claim", "app-version", "environment")
  _, err = customFilter.Filter(originalHeaders)
  if err != nil {
    fmt.Printf("failed to filter custom headers: %s\n", err)
    return
  }

  // Filter 2: Extract only standard fields using StandardHeadersFilter
  standardFilter := jws.StandardHeadersFilter()
  _, err = standardFilter.Filter(originalHeaders)
  if err != nil {
    fmt.Printf("failed to filter standard headers: %s\n", err)
    return
  }

  // Filter 3: Remove sensitive custom fields using Reject
  sensitiveFilter := jws.NewHeaderNameFilter("custom-claim")
  _, err = sensitiveFilter.Reject(originalHeaders)
  if err != nil {
    fmt.Printf("failed to reject sensitive headers: %s\n", err)
    return
  }

  // OUTPUT:
}
```
source: [examples/jws_filter_basic_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_filter_basic_example_test.go)
<!-- END INCLUDE -->

## Advanced header filtering

For more complex filtering scenarios, including multi-signature JWS messages:

<!-- INCLUDE(examples/jws_filter_advanced_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_header_filter_advanced() {
  // Create keys for multi-signature JWS
  key1, err := jwk.Import([]byte(`secret-key-1`))
  if err != nil {
    fmt.Printf("failed to create key1: %s\n", err)
    return
  }

  key2, err := jwk.Import([]byte(`secret-key-2`))
  if err != nil {
    fmt.Printf("failed to create key2: %s\n", err)
    return
  }

  // Create complex headers for first signature
  headers1 := jws.NewHeaders()
  headers1.Set(jws.KeyIDKey, "primary-key")
  headers1.Set("service", "auth-service")
  headers1.Set("version", "2.1")
  headers1.Set("security-level", "high")
  headers1.Set("internal-use", "true")

  // Create headers for second signature with different custom fields
  headers2 := jws.NewHeaders()
  headers2.Set(jws.KeyIDKey, "backup-key")
  headers2.Set("service", "backup-auth")
  headers2.Set("datacenter", "us-west")
  headers2.Set("backup-priority", "1")
  headers2.Set("internal-use", "false")

  payload := []byte(`{"action": "login", "timestamp": 1609459200}`)

  // Create a multi-signature JWS message using JSON serialization
  signed, err := jws.Sign(payload, jws.WithJSON(),
    jws.WithKey(jwa.HS256(), key1, jws.WithProtectedHeaders(headers1)),
    jws.WithKey(jwa.HS256(), key2, jws.WithProtectedHeaders(headers2)))
  if err != nil {
    fmt.Printf("failed to sign message: %s\n", err)
    return
  }

  // Parse the signed message
  parsedMsg, err := jws.Parse(signed)
  if err != nil {
    fmt.Printf("failed to parse message: %s\n", err)
    return
  }

  // Advanced filtering scenarios
  for i, sig := range parsedMsg.Signatures() {
    originalHeaders := sig.ProtectedHeaders()

    // Use case 1: Filter by service-related fields
    serviceFilter := jws.NewHeaderNameFilter("service", "datacenter", "backup-priority")
    _, err := serviceFilter.Filter(originalHeaders)
    if err != nil {
      fmt.Printf("failed to filter service headers: %s\n", err)
      continue
    }

    // Use case 2: Create public headers (remove internal fields)
    internalFilter := jws.NewHeaderNameFilter("internal-use", "security-level")
    _, err = internalFilter.Reject(originalHeaders)
    if err != nil {
      fmt.Printf("failed to create public headers: %s\n", err)
      continue
    }

    // Use case 3: Combine standard filter with custom filtering
    standardFilter := jws.StandardHeadersFilter()
    customFieldsOnly, err := standardFilter.Reject(originalHeaders)
    if err != nil {
      fmt.Printf("failed to extract custom fields: %s\n", err)
      continue
    }

    // Then filter custom fields for specific categories
    operationalFilter := jws.NewHeaderNameFilter("service", "version", "datacenter")
    _, err = operationalFilter.Filter(customFieldsOnly)
    if err != nil {
      fmt.Printf("failed to filter operational headers: %s\n", err)
      continue
    }

    if i == 0 {
      // Use case 4: Validate security requirements for first signature
      validateJWSSecurityHeaders(originalHeaders)
    }
  }

  // OUTPUT:
}

// Helper function to demonstrate validation using filtered JWS headers
func validateJWSSecurityHeaders(headers jws.Headers) {
  // Check security level
  var secLevel string
  if err := headers.Get("security-level", &secLevel); err != nil {
    fmt.Println("✗ Security level not found")
  }

  // Check internal use flag
  var internalUse string
  if err := headers.Get("internal-use", &internalUse); err != nil {
    fmt.Println("✗ Internal use flag missing")
  }

  // Check service identification
  var service string
  if err := headers.Get("service", &service); err != nil {
    fmt.Println("✗ Service identification missing")
  }
}
```
source: [examples/jws_filter_advanced_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jws_filter_advanced_example_test.go)
<!-- END INCLUDE -->
