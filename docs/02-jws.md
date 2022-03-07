# Working with JWS

In this document we describe how to work with JWS using [`github.com/lestrrat-go/jwx/v2/jws`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws)

* [Parsing](#parsing)
  * [Getting the payload from a JWS encoded buffer](#getting-the-payload-from-a-jws-encoded-buffer)
  * [Parse a JWS encoded buffer into a jws.Message](#parse-a-jws-encoded-buffer-into-a-jwsmessage)
  * [Parse a JWS encoded message stored in a file](#parse-a-jws-encoded-message-stored-in-a-file)
* [Signing](#signing)
  * [Generating a JWS message in compact serialization format](#generating-a-jws-message-in-compact-serialization-format)
  * [Generating a JWS message in JSON serialization format](#generating-a-jws-message-in-json-serialization-format)
  * [Generating a JWS message with detached payload](#generating-a-jws-with-detached-payload)
  * [Using cloud KMS services](#using-cloud-kms-services)
* [Verifying](#verifying)
  * [Verification using `jku`](#verification-using-jku)
* [Using a custom signing/verification algorithm](#using-a-customg-signingverification-algorithm)
* [Enabling ES256K](#enabling-es256k)
# Parsing

## Getting the payload from a JWS encoded buffer

If you want to get the payload in the JWS message after it has been verified, use [`jws.Verify()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Verify)

```go
var encoded = []byte{...}
payload, _ := jws.Verify(encoded, jws.WithKey(alg, key))
```

You must provide the algorithm and the public key to use for verification.
Please read "[Why don't you automatically infer the algorithm for `jws.Verify`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)"

If the algorithm or the key does not match, an error is returned.

## Parse a JWS encoded buffer into a jws.Message

You can parse a JWS buffer into a [`jws.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Message) object. In this mode, there is no verification performed.

```go
var payload = []byte{...}
msg, _ := jws.Parse(payload)
```

Note that [`jws.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Message) is not really built for general signing/verification usage.
It's built more so for inspection purposes.
Think twice before attempting to do anything more than inspection using [`jws.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Message).

## Parse a JWS encoded message stored in a file

To parse a JWS stored in a file, use [`jws.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#ReadFile). [`jws.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#ReadFile) accepts the same options as [`jws.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Parse).

```go
message, _ := jws.ReadFile(`message.jws`)
```

## Verify a JWS with detached payload

To parse a JWS with detached payload, use the `jws.WithDetachedPayload()` option:

```go
signed, _ := jws.Verify(signed, jws.WithKey(alg, key), jws.WithDetachedPayload(payload))
```

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
  "log"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_Sign() {
  key, err := jwk.New([]byte(`abracadavra`))
  if err != nil {
    log.Printf("failed to create key: %s", err)
    return
  }

  buf, err := jws.Sign([]byte("Lorem ipsum"), jws.WithKey(jwa.HS256, key))
  if err != nil {
    log.Printf("failed to sign payload: %s", err)
    return
  }
  fmt.Printf("%s\n", buf)
  // OUTPUT:
  // eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo
}
```
source: [examples/jws_sign_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_sign_example_test.go)
<!-- END INCLUDE -->

## Generating a JWS message in JSON serialization format

Generally the only time you need to use a JSON serialization format is when you have to generate multiple signatures for a given payload using multiple signing algorithms and keys.

When this need arises, use the [`jws.Sign()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Sign) function with the `jws.WithJSON()` option and multiple `jwt.WithKey()` options:

```go
signed, _ := jws.Sign(payload,
  jws.WithJSON(),
  jws.WithKey(alg1, key1),
  jws.WithKey(alg2, key2),
)
```

## Generating a JWS message with detached payload

JWS messages can be constructed with a detached payload. Use the `jws.WithDetachedPayload()` option to
create a JWS message with the message detached from the result.

<!-- INCLUDE(examples/jws_sign_detached_payload_example_test.go) -->
<!-- END INCLUDE -->

## Including Arbitrary Headers to Compact Serialization

By default, only some header fields are included in the result from `jws.Sign()`.
If you want to include more headers fields in the resulting JWS, you will have to provide them via the `jws.WithHeaders()` option

```go
hdrs := jws.NewHeaders()
hdrs.Set(`arbitrary-key`, `value`)
signed, _ := jws.Sign(payload, jws.WithKey(alg, key, jws.WithProtected(hdrs)))
```

Even if you need to pass in custom headers, normally you should only need to set the protected headers.

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
  "log"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_VerifyWithKey() {
  const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo`

  key, err := jwk.New([]byte(`abracadavra`))
  if err != nil {
    log.Printf("failed to create key: %s", err)
    return
  }

  buf, err := jws.Verify([]byte(src), jws.WithKey(jwa.HS256, key))
  if err != nil {
    log.Printf("failed to sign payload: %s", err)
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

To verify a payload using JWKS, by default you will need your payload and JWKS to have matching `alg` field.

The `alg` field's requirement is the same for using a single key. See "[Why don't you automatically infer the algorithm for `jws.Verify`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)"

Note that unlike in JWT, the `kid` is not required by default, although you _can_ make it so
by passing `jws.WithRequireKid(true)`.

For more discussion on why/how `alg`/`kid` values work, please read the [relevant section in the JWT documentation](01-jwt.md#parse-and-verify-a-jwt-with-a-key-set-matching-kid)

<!-- INCLUDE(examples/jws_verify_with_keyset_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "log"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_VerifyWithKey() {
  const src = `eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0.idbECxA8ZhQbU0ddZmzdRZxQmHjwvw77lT2bwqGgNMo`

  key, err := jwk.New([]byte(`abracadavra`))
  if err != nil {
    log.Printf("failed to create key: %s", err)
    return
  }

  buf, err := jws.Verify([]byte(src), jws.WithKey(jwa.HS256, key))
  if err != nil {
    log.Printf("failed to sign payload: %s", err)
    return
  }
  fmt.Printf("%s\n", buf)
  // OUTPUT:
  // Lorem ipsum
}
```
source: [examples/jws_verify_with_key_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jws_verify_with_key_example_test.go)
<!-- END INCLUDE -->

## Verification using a detached payload

To verify a JWS message with detached payload, use the `jws.WithDetachedPayload()` option:

<!-- INCLUDE(examples/jws_verify_detached_payload_example_test.go) -->
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
  "crypto/ed25519"
  "crypto/rand"
  "fmt"

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
