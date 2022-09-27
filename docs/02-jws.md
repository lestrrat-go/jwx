# Working with JWS

In this document we describe how to work with JWS using [`github.com/lestrrat-go/jwx/v2/jws`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws)

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
* [Using a custom signing/verification algorithm](#using-a-customg-signingverification-algorithm)
* [Enabling ES256K](#enabling-es256k)

# Parsing

Parsing a JWS message means taking either a JWS message serialized in JSON or Compact form
and loading it into a `jws.Message` object. No verification is performed, and therefore
you cannot "trust" the contents in the same way that a verified message could be trusted.

Also, be aware that a `jws.Message` is not meant to be used for either signing or
verification. It is only provided such that it can be inspected -- there is no way
to sign or verify using a parsed `jws.Message`. To do this, you would need to use
`jws.Sign()` or `jws.Message()`.

## Parse a JWS message stored in memory

You can parse a JWS message in memory stored as `[]byte` into a [`jws.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Message) object. In this mode, there is no verification performed.

<!-- INCLUDE(examples/jws_parse_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_Parse() {
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
source: [examples/jws_parse_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_parse_example_test.go)
<!-- END INCLUDE -->

## Parse a JWS message stored in a file

To parse a JWS stored in a file, use [`jws.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#ReadFile). [`jws.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#ReadFile) accepts the same options as [`jws.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Parse).

<!-- INCLUDE(examples/jws_readfile_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_ReadFile() {
  const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo`
  f, err := os.CreateTemp(``, `jws_readfile-*.jws`)
  if err != nil {
    fmt.Printf("failed to create temporary file: %s\n", err)
    return
  }
  defer os.Remove(f.Name())

  fmt.Fprintf(f, src)
  f.Close()

  msg, err := jws.ReadFile(f.Name())
  if err != nil {
    fmt.Printf("failed to parse JWS message: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(msg)

  // OUTPUT:
  // {"payload":"TG9yZW0gaXBzdW0","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo"}
}
```
source: [examples/jws_readfile_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_readfile_example_test.go)
<!-- END INCLUDE -->

## Parse a JWS message and access JWS headers

Note: If you are considering using JWS header fields to decide on which key to use for verification, consider [using a `jwt.KeyProvider`](./01-jwt.md#parse-and-verify-a-jwt-using-arbitrary-keys).

While a lot of documentation in the wild treat as if a JWT message encoded in base64 is... a JWT message, in truth it is a JWT message enveloped in a JWS message. Therefore in order to access the JWS headers of a JWT message you will need to work witha `jws.Message` object, which you can obtain from parsing the JWS payload. You will need to understand [the structure of a generic JWS message](https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1).

Below sample code extracts the `kid` field of a single-signature JWS message:

<!-- INCLUDE(examples/jws_use_jws_header_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWS_UseJWSHeader() {
  key, err := jwk.FromRaw([]byte(`abracadabra`))
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

  signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, key))
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
  // a generic JWS message may have multiple signatures. Therefore we
  // need to access the first element
  fmt.Printf("%q\n", msg.Signatures()[0].ProtectedHeaders().KeyID())
  // OUTPUT:
  // "secret-key"
}
```
source: [examples/jws_use_jws_header_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_use_jws_header_test.go)
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

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_Sign() {
  key, err := jwk.FromRaw([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create key: %s\n", err)
    return
  }

  buf, err := jws.Sign([]byte("Lorem ipsum"), jws.WithKey(jwa.HS256, key))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", buf)
  // OUTPUT:
  // eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.EjVtju0uXjSz6QevNgAqN1ESd9aNCP7-tJLifkQ0_C0
}
```
source: [examples/jws_sign_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_sign_example_test.go)
<!-- END INCLUDE -->

## Generating a JWS message in JSON serialization format

Generally the only time you need to use a JSON serialization format is when you have to generate multiple signatures for a given payload using multiple signing algorithms and keys.

When this need arises, use the [`jws.Sign()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Sign) function with the `jws.WithJSON()` option and multiple `jws.WithKey()` options:

<!-- INCLUDE(examples/jws_sign_json_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_SignJSON() {
  var keys []jwk.Key

  for i := 0; i < 3; i++ {
    key, err := jwk.FromRaw([]byte(fmt.Sprintf(`abracadabra-%d`, i)))
    if err != nil {
      fmt.Printf("failed to create key: %s\n", err)
      return
    }
    keys = append(keys, key)
  }

  options := []jws.SignOption{jws.WithJSON()}
  for _, key := range keys {
    options = append(options, jws.WithKey(jwa.HS256, key))
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
source: [examples/jws_sign_json_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_sign_json_example_test.go)
<!-- END INCLUDE -->

## Generating a JWS message with detached payload

JWS messages can be constructed with a detached payload. Use the `jws.WithDetachedPayload()` option to
create a JWS message with the message detached from the result.

<!-- INCLUDE(examples/jws_sign_detached_payload_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_SignDetachedPayload() {
  payload := `$.02`

  key, err := jwk.FromRaw([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create symmetric key: %s\n", err)
    return
  }

  serialized, err := jws.Sign(nil, jws.WithKey(jwa.HS256, key), jws.WithDetachedPayload([]byte(payload)))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }

  fmt.Printf("%s\n", serialized)
  // OUTPUT:
  // eyJhbGciOiJIUzI1NiJ9..H14oXKwyvAsl0IbBLjw9tLxNIoYisuIyb_oDV4-30Vk
}
```
source: [examples/jws_sign_detached_payload_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_sign_detached_payload_example_test.go)
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

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_SignWithHeaders() {
  key, err := jwk.FromRaw([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create key: %s\n", err)
    return
  }

  hdrs := jws.NewHeaders()
  hdrs.Set(`x-example`, true)
  buf, err := jws.Sign([]byte("Lorem ipsum"), jws.WithKey(jwa.HS256, key, jws.WithProtectedHeaders(hdrs)))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", buf)
  // OUTPUT:
  // eyJhbGciOiJIUzI1NiIsIngtZXhhbXBsZSI6dHJ1ZX0.TG9yZW0gaXBzdW0.9nIX0hN7u1b97UcjmrVvd5y1ubkQp_1gz1V3Mkkcm14
}
```
source: [examples/jws_sign_with_headers_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_sign_with_headers_example_test.go)
<!-- END INCLUDE -->

## Using cloud KMS services

If you want to use cloud KMSes such as AWS KMS to sign and verify payloads, look for an object that implements
`crypto.Signer`. There are some [implementations written for this module](https://github.com/jwx-go/crypto-signer).

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

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_VerifyWithKey() {
  const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.EjVtju0uXjSz6QevNgAqN1ESd9aNCP7-tJLifkQ0_C0`

  key, err := jwk.FromRaw([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create key: %s\n", err)
    return
  }

  buf, err := jws.Verify([]byte(src), jws.WithKey(jwa.HS256, key))
  if err != nil {
    fmt.Printf("failed to verify payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", buf)
  // OUTPUT:
  // Lorem ipsum
}
```
source: [examples/jws_verify_with_key_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_verify_with_key_example_test.go)
<!-- END INCLUDE -->

## Verification using a JWKS

To verify a payload using JWKS, by default you will need your payload and JWKS to have matching `kid` and `alg` fields.

The `alg` field's requirement is the same for using a single key. See "[Why don't you automatically infer the algorithm for `jws.Verify`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)"

The `kid` field by default must match between the JWS signature and the key in JWKS. This can be explictly disabled by specifying `jws.WithRequireKid(false)` suboption when using the `jws.WithKeySet()` option (i.e.: `jws.WithKeySet(keyset, jws.WithRequireKid(false))`)

For more discussion on why/how `alg`/`kid` values work, please read the [relevant section in the JWT documentation](01-jwt.md#parse-and-verify-a-jwt-with-a-key-set-matching-kid)

<!-- INCLUDE(examples/jws_verify_with_keyset_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_VerifyWithJWKSet() {
  // Setup payload first...
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to create private key: %s\n", err)
    return
  }
  const payload = "Lorem ipsum"
  signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256, privkey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }

  // Create a JWK Set
  set := jwk.NewSet()
  // Add some bogus keys
  k1, _ := jwk.FromRaw([]byte("abracadabra"))
  set.AddKey(k1)
  k2, _ := jwk.FromRaw([]byte("opensesame"))
  set.AddKey(k2)
  // AddKey the real thing
  pubkey, _ := jwk.PublicRawKeyOf(privkey)
  k3, _ := jwk.FromRaw(pubkey)
  k3.Set(jwk.AlgorithmKey, jwa.RS256)
  set.AddKey(k3)

  // Up to this point, you probably will replace with a simple jwk.Fetch()

  // Now verify using the set.
  if _, err := jws.Verify(signed, jws.WithKeySet(set, jws.WithRequireKid(false))); err != nil {
    fmt.Printf("Failed to verify using jwk.Set: %s", err)
  }

  // OUTPUT:
}
```
source: [examples/jws_verify_with_keyset_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_verify_with_keyset_example_test.go)
<!-- END INCLUDE -->

## Verification using a detached payload

To verify a JWS message with detached payload, use the `jws.WithDetachedPayload()` option:

<!-- INCLUDE(examples/jws_verify_detached_payload_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_VerifyDetachedPayload() {
  serialized := `eyJhbGciOiJIUzI1NiJ9..H14oXKwyvAsl0IbBLjw9tLxNIoYisuIyb_oDV4-30Vk`
  payload := `$.02`

  key, err := jwk.FromRaw([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create symmetric key: %s\n", err)
    return
  }

  verified, err := jws.Verify([]byte(serialized), jws.WithKey(jwa.HS256, key), jws.WithDetachedPayload([]byte(payload)))
  if err != nil {
    fmt.Printf("failed to verify payload: %s\n", err)
    return
  }

  fmt.Printf("%s\n", verified)
  // OUTPUT:
  // $.02
}
```
source: [examples/jws_verify_detached_payload_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_verify_detached_payload_example_test.go)
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

In such scenarios, you can use the [`jws.RegisterSigner()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#RegisterSigner) and [`jws.RegisterVerifier()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#RegisterVerifier) functions to
generate your own verifier instance. 

<!-- INCLUDE(examples/jws_custom_signer_verifier_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "fmt"

  "github.com/cloudflare/circl/sign/ed25519"
  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jws"
)

type CirclEdDSASignerVerifier struct{}

func NewCirclEdDSASigner() (jws.Signer, error) {
  return &CirclEdDSASignerVerifier{}, nil
}

func NewCirclEdDSAVerifier() (jws.Verifier, error) {
  return &CirclEdDSASignerVerifier{}, nil
}

func (s CirclEdDSASignerVerifier) Algorithm() jwa.SignatureAlgorithm {
  return jwa.EdDSA
}

func (s CirclEdDSASignerVerifier) Sign(payload []byte, keyif interface{}) ([]byte, error) {
  switch key := keyif.(type) {
  case ed25519.PrivateKey:
    return ed25519.Sign(key, payload), nil
  default:
    return nil, fmt.Errorf(`invalid key type %T`, keyif)
  }
}

func (s CirclEdDSASignerVerifier) Verify(payload []byte, signature []byte, keyif interface{}) error {
  switch key := keyif.(type) {
  case ed25519.PublicKey:
    if ed25519.Verify(key, payload, signature) {
      return nil
    }
    return fmt.Errorf(`failed to verify EdDSA signature`)
  default:
    return fmt.Errorf(`invalid key type %T`, keyif)
  }
}

func ExampleJWS_CustomSignerVerifier() {
  // This example shows how to register external jws.Signer / jws.Verifier for
  // a given algorithm.
  jws.RegisterSigner(jwa.EdDSA, jws.SignerFactoryFn(NewCirclEdDSASigner))
  jws.RegisterVerifier(jwa.EdDSA, jws.VerifierFactoryFn(NewCirclEdDSAVerifier))

  pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
  if err != nil {
    fmt.Printf(`failed to generate keys: %s`, err)
    return
  }

  const payload = "Lorem Ipsum"
  signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.EdDSA, privkey))
  if err != nil {
    fmt.Printf(`failed to generate signed message: %s`, err)
    return
  }

  verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSA, pubkey))
  if err != nil {
    fmt.Printf(`failed to verify signed message: %s`, err)
    return
  }

  if string(verified) != payload {
    fmt.Printf(`got invalid payload: %s`, verified)
    return
  }

  // OUTPUT:
}
```
source: [examples/jws_custom_signer_verifier_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_custom_signer_verifier_example_test.go)
<!-- END INCLUDE -->

# Enabling ES256K

See [Enabling Optional Signature Methods](./20-global-settings.md#enabling-optional-signature-methods)
