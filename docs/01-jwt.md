# Working with JWT

In this document we describe how to work with JWT using `github.com/lestrrat-go/jwx/v2/jwt`

* [Terminology](#terminology)
  * [Verification](#verification)
  * [Validation](#validation)
* [Parsing](#parsing)
  * [Parse a JWT](#parse-a-jwt)
  * [Parse a JWT from file](#parse-a-jwt-from-file)
  * [Parse a JWT from a *http.Request](#parse-a-jwt-from-a-httprequest)
* [Programmatically Creating a JWT](#programmatically-creating-a-jwt)
  * [Using jwt.New](#using-jwt-new)
  * [Using Builder](#using-builder)
* [Verification](#jwt-verification)
  * [Parse and Verify a JWT (with a single key)](#parse-and-verify-a-jwt-with-single-key)
  * [Parse and Verify a JWT (with a key set, matching "kid")](#parse-and-verify-a-jwt-with-a-key-set-matching-kid)
  * [Parse and Verify a JWT (using arbitrary keys)](#parse-and-verify-a-jwt-using-arbitrary-keys)
  * [Parse and Verify a JWT (using key specified in "jku")](#parse-and-verify-a-jwt-using-key-specified-in-jku)
* [Validation](#jwt-validation)
  * [Validate for specific claims](#validate-for-specific-claims)
  * [Use a custom validator](#use-a-custom-validator)
  * [Detecting error types](#detecting-error-types)
* [Serialization](#jwt-serialization)
  * [Serialize using JWS](#serialize-using-jws)
  * [Serialize using JWE and JWS](#serialize-using-jwe-and-jws)
  * [Serialize the `aud` field as a string](#serialize-aud-field-as-a-string)
* [Working with JWT](#working-with-jwt)
  * [Access JWS headers](#access-jws-headers)
  * [Get/Set fields](#getset-fields)

---

# Terminology

## Verification

We use the terms "verify" and "verification" to describe the process of ensuring the integrity of the JWT, namely the signature verification.

## Validation

We use the terms "validate" and "validation" to describe the process of checking the contents of a JWT, for example if the values in fields such as "iss", "sub", "aud" match our expected values, and/or if the token has expired.

# Parsing

Parsing a (possibly) JWT comprises of multiple distinct operations. Typically your JWTs are signed and serialized as JWS messages. The JWT is _enveloped_ in JWS. The following is a [sample JWS message serialized in compact form](https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1):

```
eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX
```

This message is comprised of three data segments encoded in `base64`, concatenated with a `.`. Each part reads as follows:

* **Part 1**: The JWS protected headers. These are metadata required to verify the signed payload.
* **Part 2**: The JWS payload. This can be any arbitrary data, but in our case it would be a JWT object.
* **Part 3**: The JWS signature. This is the signature generated from the signinig key, the headers, and the payload.

It is important to realize that JWS in itself has nothing to do with JWT. The envelope and therefore the JWS mechanism itself does not care that the payload is JWT or not.

Once we verify the integrity of the payload using JWS verification, the payload can then be trusted to be untampered.
Therefore, while the JWS payload _could_ theoretically be decoded as a JWT object before verification, its contents
should not be trusted -- e.g. it should not be used to store information that has to do with verification.

The `jwt.Parse()` function in this package not only provides ways to decode a JWT object from JSON, but it also
provides convenient ways to perform the above verification and decoding of the JWT object in one go,
as well as validating the contents of the JWT object after it has been decoded.

## Parse a JWT

To parse a JWT in either raw JSON or JWS compact serialization format, use [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Parse)

<!-- INCLUDE(examples/jwt_parse_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_Parse() {
  tok, err := jwt.Parse(jwtSignedWithHS256, jwt.WithKey(jwa.HS256, jwkSymmetricKey))
  if err != nil {
    fmt.Printf("%s\n", err)
    return
  }
  _ = tok
  // OUTPUT:
}
```
source: [examples/jwt_parse_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_parse_example_test.go)
<!-- END INCLUDE -->

Note that the above form does NOT perform any signature verification, or validation of the JWT token itself.
This just reads the contents of src, and maps it into the token, period.
In order to perform verification/validation, please see the methods described elsewhere in this document, and pass the appropriate option(s).

## Parse a JWT from file

To parsea JWT stored in a file, use [`jwt.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#ReadFile). [`jwt.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#ReadFile) accepts the same options as [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Parse).

<!-- INCLUDE(examples/jwt_readfile_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ReadFile() {
  f, err := os.CreateTemp(``, `jwt_readfile-*.jws`)
  if err != nil {
    fmt.Printf("failed to create temporary file: %s\n", err)
    return
  }
  defer os.Remove(f.Name())

  fmt.Fprintf(f, exampleJWTSignedHMAC)
  f.Close()

  // Note: this JWT has NOT been verified because we have not
  // passed jwt.WithKey() et al. You need to pass these values
  // if you want the token to be parsed and verified in one go
  tok, err := jwt.ReadFile(f.Name(), jwt.WithVerify(false), jwt.WithValidate(false))
  if err != nil {
    fmt.Printf("failed to read file %q: %s\n", f.Name(), err)
    return
  }
  _ = tok
  // OUTPUT:
}
```
source: [examples/jwt_readfile_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_readfile_example_test.go)
<!-- END INCLUDE -->

## Parse a JWT from a *http.Request

To parse a JWT stored within a *http.Request object, use [`jwt.ParseRequest()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#ParseRequest). It by default looks for JWTs stored in the "Authorization" header, but can be configured to look under other headers and within the form fields.

<!-- INCLUDE(examples/jwt_parse_request_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "net/http"
  "net/url"
  "strings"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ParseRequest_Authorization() {
  values := url.Values{
    `access_token`: []string{exampleJWTSignedHMAC},
  }

  req, err := http.NewRequest(http.MethodGet, `https://github.com/lestrrat-go/jwx`, strings.NewReader(values.Encode()))
  if err != nil {
    fmt.Printf("failed to create request: %s\n", err)
    return
  }

  req.Header.Set(`Authorization`, fmt.Sprintf(`Bearer %s`, exampleJWTSignedECDSA))
  req.Header.Set(`X-JWT-Token`, exampleJWTSignedRSA)

  testcases := []struct {
    options []jwt.ParseOption
  }{
    // No options - looks under "Authorization" header
    {},
    // Looks under "X-JWT-Token" header only
    {
      options: []jwt.ParseOption{jwt.WithHeaderKey(`X-JWT-Token`)},
    },
    // Looks under "Authorization" and "X-JWT-Token" headers
    {
      options: []jwt.ParseOption{jwt.WithHeaderKey(`Authorization`), jwt.WithHeaderKey(`X-JWT-Token`)},
    },
    // Looks under "Authorization" header and "access_token" form field
    {
      options: []jwt.ParseOption{jwt.WithFormKey(`access_token`)},
    },
  }

  for _, tc := range testcases {
    options := append(tc.options, []jwt.ParseOption{jwt.WithVerify(false), jwt.WithValidate(false)}...)
    tok, err := jwt.ParseRequest(req, options...)
    if err != nil {
      fmt.Printf("jwt.ParseRequest with options %#v failed: %s\n", tc.options, err)
      return
    }
    _ = tok
  }
  // OUTPUT:
}
```
source: [examples/jwt_parse_request_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_parse_request_example_test.go)
<!-- END INCLUDE -->

# Programmatically Creating a JWT

## Using `jwt.New`

The most straight forward way is to use the constructor `jwt.New()` and use `(jwt.Token).Set()`:

<!-- INCLUDE(examples/jwt_construct_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_Construct() {
  tok := jwt.New()
  if err := tok.Set(jwt.IssuerKey, `github.com/lestrrat-go/jwx`); err != nil {
    fmt.Printf("failed to set claim: %s\n", err)
    return
  }
  if err := tok.Set(jwt.AudienceKey, `users`); err != nil {
    fmt.Printf("failed to set claim: %s\n", err)
    return
  }

  if err := json.NewEncoder(os.Stdout).Encode(tok); err != nil {
    fmt.Printf("failed to encode to JSON: %s\n", err)
    return
  }
  // OUTPUT:
  // {"aud":["users"],"iss":"github.com/lestrrat-go/jwx"}
}
```
source: [examples/jwt_construct_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_construct_example_test.go)
<!-- END INCLUDE -->

If repeatedly checking for errors in `Set()` sounds like too much trouble, consider using the builder.

## Using Builder

Since v1.2.12, the `jwt` package comes with a builder, which you can use to initialize a JWT token in (almost) one go.
For known fields, you can use the special methods such as `Issuer()` and `Audience()`. For other claims
you can use the `Claim()` method.

One caveat that you should be aware about is that all calls to set a claim in the builder performs an _overwriting_
operation. If you set the same claim multiple times, the last value is used.

<!-- INCLUDE(examples/jwt_builder_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_Builder() {
  tok, err := jwt.NewBuilder().
    Claim(`claim1`, `value1`).
    Claim(`claim2`, `value2`).
    Issuer(`github.com/lestrrat-go/jwx`).
    Audience([]string{`users`}).
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }
  if err := json.NewEncoder(os.Stdout).Encode(tok); err != nil {
    fmt.Printf("failed to encode to JSON: %s\n", err)
    return
  }
  // OUTPUT:
  // {"aud":["users"],"claim1":"value1","claim2":"value2","iss":"github.com/lestrrat-go/jwx"}
}
```
source: [examples/jwt_builder_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_builder_example_test.go)
<!-- END INCLUDE -->

# JWT Verification

## Parse and Verify a JWT (with single key)

To parse a JWT *and* verify that its content matches the signature as described in the JWS message, you need to add some options when calling the [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Parse) function.

<!-- INCLUDE(examples/jwt_parse_with_key_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ParseWithKey() {
  const keysrc = `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`

  key, err := jwk.ParseKey([]byte(keysrc))
  if err != nil {
    fmt.Printf("jwk.ParseKey failed: %s\n", err)
    return
  }

  tok, err := jwt.Parse([]byte(exampleJWTSignedHMAC), jwt.WithKey(jwa.HS256, key), jwt.WithValidate(false))
  if err != nil {
    fmt.Printf("jwt.Parse failed: %s\n", err)
    return
  }
  _ = tok
  // OUTPUT:
}
```
source: [examples/jwt_parse_with_key_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_parse_with_key_example_test.go)
<!-- END INCLUDE -->

In the above example, `key` may either be the raw key (i.e. "crypto/ecdsa".PublicKey, "crypto/ecdsa".PrivateKey) or an instance of [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Key) (i.e. [`jwk.ECDSAPrivateKey`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#ECDSAPrivateKey), [`jwk.ECDSAPublicKey`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#ECDSAPublicKey)). The key type must match the algorithm being used.

## Parse and Verify a JWT (with a key set, matching "kid")

To parse a JWT *and* verify that its content matches the signature as described in the JWS message using a [`jwk.Set`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Set), you need to add some options when calling the [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Parse) function.

The following code does a lot of preparation to mimic a real JWKS signed JWT, but the code required in the user side is located towards the end.

In real life, the location of JWKS files are specified by the service that provided you with the signed JWT. The URL for these JWKS files often (but are not always guaranteed to be) take the form `https://DOMAIN/.well-known/jwks.json` and the like. If you need to fetch these in your code, [refer to the documentation on `jwk` package](04-jwk.md#fetching-jwk-sets).

<!-- INCLUDE(examples/jwt_parse_with_keyset_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ParseWithKeySet() {
  var serialized []byte
  var signingKey jwk.Key
  var keyset jwk.Set

  // Preparation:
  //
  // For demonstration purposes, we need to do some preparation
  // Create a JWK key to sign the token (and also give a KeyID),
  {
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
      fmt.Printf("failed to generate private key: %s\n", err)
      return
    }
    // This is the key we will use to sign
    realKey, err := jwk.FromRaw(privKey)
    if err != nil {
      fmt.Printf("failed to create JWK: %s\n", err)
      return
    }
    realKey.Set(jwk.KeyIDKey, `mykey`)
    realKey.Set(jwk.AlgorithmKey, jwa.RS256)

    // For demonstration purposes, we also create a bogus key
    bogusKey, err := jwk.FromRaw([]byte("bogus"))
    if err != nil {
      fmt.Printf("failed to create bogus JWK: %s\n", err)
      return
    }
    bogusKey.Set(jwk.AlgorithmKey, jwa.NoSignature)
    bogusKey.Set(jwk.KeyIDKey, "otherkey")

    // Now create a key set that users will use to verity the signed serialized against
    // Normally these keys are available somewhere like https://www.googleapis.com/oauth2/v3/certs
    // This key set contains two keys, the first one is the correct one

    // We can use the jwk.PublicSetOf() utility to get a JWKS
    // all of the public keys
    {
      privset := jwk.NewSet()
      privset.AddKey(realKey)
      privset.AddKey(bogusKey)
      v, err := jwk.PublicSetOf(privset)
      if err != nil {
        fmt.Printf("failed to create public JWKS: %s\n", err)
        return
      }
      keyset = v
    }

    signingKey = realKey
  }

  // Create the token
  token := jwt.New()
  token.Set(`foo`, `bar`)

  // Sign the token and generate a JWS message
  signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, signingKey))
  if err != nil {
    fmt.Printf("failed to generate signed serialized: %s\n", err)
    return
  }

  // This is what you typically get as a signed JWT from a server
  serialized = signed

  // Actual verification:
  // FINALLY. This is how you Parse and verify the serialized.
  // Key IDs are automatically matched.
  // There was a lot of code above, but as a consumer, below is really all you need
  // to write in your code
  tok, err := jwt.Parse(
    serialized,
    // Tell the parser that you want to use this keyset
    jwt.WithKeySet(keyset),

    // Replace the above option with the following option if you know your key
    // does not have an "alg"/ field (which is apparently the case for Azure tokens)
    // jwt.WithKeySet(keyset, jws.WithInferAlgorithmFromKey(true)),
  )
  if err != nil {
    fmt.Printf("failed to parse serialized: %s\n", err)
  }
  _ = tok
  // OUTPUT:
}
```
source: [examples/jwt_parse_with_keyset_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_parse_with_keyset_example_test.go)
<!-- END INCLUDE -->

There are a couple of things to note.

First is that the signing key is initialized with key ID (`kid`). By using a `jwk.Key` with `kid` field set,
the resulting JWS message will also have the field `kid` set to the same value in the
corresponding protected headers. This is set because the default behavior is to ONLY accept
keys if they have matching `kid` fields as the JWS protecte headers.

You may override this behavior if you explicitly specify to to turn this off using
the `jws.WithRequireKid(false)` option, but this is not recommended. If you already
know which is supposed to work before hand, it is recommended that you parse the `jwk.Set`
and modify it manually so that it has a proper `kid` field. Unlike using `jws.WithRequireKid(false)`
option, this will not allow unintended keys to slip by and have the verification succeed.

Second, notice that there's a commented out section in the above code where it uses an extra suboption
`jws.WithInferAlgorithmFromKey()` in the `jwt.Parse()` call. The above examples will correctly
verify the message as we explicitly set the `alg` with a proper value. However, if the key in your
particular JWKS does not contain an `alg` field, the above example would fail.

This is because we default on the side of safety and require the `alg` field of the key to contain
the actual algorithm.The general stance that we take when verifying JWTs is that we don't really
trust what the values on the JWT (or actually, the JWS message) says, so we don't just use their
`alg` value. This is why we require that users specify the `alg` field in the `jwt.WithKey` option for single keys.

The presence of `jws.WithInferAlgorithmFromKey(true)` tells the `jws.Verify()` routine to use
heuristics to deduce the algorithm used. It's a brute-force approach, and does not always provide
the best performance. But it will try all possible algorithms available for a given key type until
one of them matches. For example, for an RSA key (either raw key or `jwk.Key`) algorithms such as RS256, RS384, RS512, PS256, PS384, and PS512 are tried.

In most cases using this suboption would Just Work. However, this type of "try until something works"
is not really recommended from a security perspective, and that is why the option is not enabled by default.

## Parse and Verify a JWT (using arbitrary keys)

If you must switch the key to use for verification dynamically, you can load your keys from any
arbitrary location using `jwt.WithKeySetProvider()` option:

<!-- INCLUDE(examples/jwt_parse_with_key_provider_example_test.go) -->
```go
package examples_test

import (
  "context"
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jws"
  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ParseWithKeyProvider() {
  // Pretend that this is a storage somewhere (maybe a database) that maps
  // a signature algorithm to a key
  store := make(map[jwa.KeyAlgorithm]interface{})
  algorithms := []jwa.SignatureAlgorithm{
    jwa.RS256,
    jwa.RS384,
    jwa.RS512,
  }
  var signingKey *rsa.PrivateKey
  for _, alg := range algorithms {
    pk, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
      fmt.Printf("failed to generate private key: %s\n", err)
      return
    }
    // too lazy to write a proper algorithm. just assign every
    // time, and signingKey will end up being the last key generated
    signingKey = pk
    store[alg] = pk.PublicKey
  }

  // Create a JWT
  token := jwt.New()
  token.Set(`foo`, `bar`)

  // Use the last private key in the list to sign the payload
  serialized, err := jwt.Sign(token, jwt.WithKey(algorithms[2], signingKey))
  if err != nil {
    fmt.Printf(`failed to sign JWT: %s`, err)
    return
  }

  // This example uses jws.KeyProviderFunc, but for production use
  // you should probably use a reusable object that implements
  // jws.KeyProvider
  tok, err := jwt.Parse(serialized, jwt.WithKeyProvider(jws.KeyProviderFunc(func(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
    alg := sig.ProtectedHeaders().Algorithm()
    key, ok := store[alg]
    if !ok {
      // nothing found
      return nil
    }

    // Note: we only send one key here, but we could potentially send _ALL_
    // keys in the store and have `jws.Verify()` try each one (but it would
    // most likely be a waste if you did that)
    sink.Key(alg, key)
    return nil
  })))
  if err != nil {
    fmt.Printf(`failed to verify JWT: %s`, err)
    return
  }
  _ = tok
  // OUTPUT:
}
```
source: [examples/jwt_parse_with_key_provider_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_parse_with_key_provider_example_test.go)
<!-- END INCLUDE -->

## Parse and Verify a JWT (using key specified in "jku")

You can parse JWTs using the JWK Set specified in the`jku` field in the JWS message by telling `jwt.Parse()` to
use `jws.VerifyAuto()` instead of `jws.Verify()`. This would effectively allow a JWS to be
self-validating.

<!-- INCLUDE(examples/jwt_parse_with_jku_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "encoding/json"
  "fmt"
  "net/http"
  "net/http/httptest"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jws"
  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ParseWithJKU() {
  set := jwk.NewSet()

  var signingKey jwk.Key

  // for _, alg := range algorithms {
  for i := 0; i < 3; i++ {
    pk, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
      fmt.Printf("failed to generate private key: %s\n", err)
      return
    }
    // too lazy to write a proper algorithm. just assign every
    // time, and signingKey will end up being the last key generated
    privkey, err := jwk.FromRaw(pk)
    if err != nil {
      fmt.Printf("failed to create jwk.Key: %s\n", err)
      return
    }
    privkey.Set(jwk.KeyIDKey, fmt.Sprintf(`key-%d`, i))

    // It is important that we are using jwk.Key here instead of
    // rsa.PrivateKey, because this way `kid` is automatically
    // assigned when we sign the token
    signingKey = privkey

    pubkey, err := privkey.PublicKey()
    if err != nil {
      fmt.Printf("failed to create public key: %s\n", err)
      return
    }
    set.AddKey(pubkey)
  }

  srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(set)
  }))
  defer srv.Close()

  // Create a JWT
  token := jwt.New()
  token.Set(`foo`, `bar`)

  hdrs := jws.NewHeaders()
  hdrs.Set(jws.JWKSetURLKey, srv.URL)

  serialized, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, signingKey, jws.WithProtectedHeaders(hdrs)))
  if err != nil {
    fmt.Printf("failed to seign token: %s\n", err)
    return
  }

  // We need to pass jwk.WithHTTPClient because we are using HTTPS,
  // and we need the certificates setup
  // We also need to explicitly setup the whitelist, this is required
  tok, err := jwt.Parse(serialized, jwt.WithVerifyAuto(nil, jwk.WithHTTPClient(srv.Client()), jwk.WithFetchWhitelist(jwk.InsecureWhitelist{})))
  if err != nil {
    fmt.Printf("failed to verify token: %s\n", err)
    return
  }
  _ = tok
  // OUTPUT:
}
```
source: [examples/jwt_parse_with_jku_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_parse_with_jku_example_test.go)
<!-- END INCLUDE -->

This feature must be used with extreme caution. Please see the caveats and fine prints
in the documentation for `jws.VerifyAuto()`

# JWT Validation

To validate if the JWT's contents, such as if the JWT contains the proper "iss","sub","aut", etc, or the expiration information and such, use the [`jwt.Validate()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Validate) function.

<!-- INCLUDE(examples/jwt_validate_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_Validate() {
  tok, err := jwt.NewBuilder().
    Issuer(`github.com/lestrrat-go/jwx`).
    Expiration(time.Now().Add(-1 * time.Hour)).
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }

  {
    // Case 1: Using jwt.Validate()
    err = jwt.Validate(tok)
    if err == nil {
      fmt.Printf("token should fail validation\n")
      return
    }
    fmt.Printf("%s\n", err)
  }

  {
    // Case 2: Using jwt.Parse()
    buf, err := json.Marshal(tok)
    if err != nil {
      fmt.Printf("failed to serialize token: %s\n", err)
      return
    }

    // NOTE: This token has NOT been verified for demonstration
    // purposes. Use `jwt.WithKey()` or the like in your production code
    _, err = jwt.Parse(buf, jwt.WithVerify(false), jwt.WithValidate(true))
    if err == nil {
      fmt.Printf("token should fail validation\n")
      return
    }
    fmt.Printf("%s\n", err)
  }
  // OUTPUT:
  // "exp" not satisfied
  // "exp" not satisfied
}
```
source: [examples/jwt_validate_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_validate_example_test.go)
<!-- END INCLUDE -->

## Validate for specific claim values

By default we only check for the time-related components of a token, such as "iat", "exp", and "nbf". To tell [`jwt.Validate()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Validate) to check for other fields, use one of the various [`jwt.ValidateOption`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#ValidateOption) values, such as `jwt.WithClaimValue()`, `jwt.WithRequiredClaim()`, etc.

<!-- INCLUDE(examples/jwt_validate_issuer_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ValidateIssuer() {
  tok, err := jwt.NewBuilder().
    Issuer(`github.com/lestrrat-go/jwx`).
    Expiration(time.Now().Add(time.Hour)).
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }

  err = jwt.Validate(tok, jwt.WithIssuer(`nobody`))
  if err == nil {
    fmt.Printf("token should fail validation\n")
    return
  }
  fmt.Printf("%s\n", err)
  // OUTPUT:
  // "iss" not satisfied: values do not match
}
```
source: [examples/jwt_validate_issuer_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_validate_issuer_example_test.go)
<!-- END INCLUDE -->

## Use a custom validator

You may also create a custom validator that implements the `jwt.Validator` interface. These validators can be added as an option to `jwt.Validate()` using `jwt.WithValidator()`. Multiple validators can be specified. The error should be of type `jwt.ValidationError`. Use `jwt.NewValidationError` to create an error of appropriate type.

<!-- INCLUDE(examples/jwt_validate_validator_example_test.go) -->
```go
package examples_test

import (
  "context"
  "errors"
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ValidateValidator() {
  validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) jwt.ValidationError {
    if t.IssuedAt().Month() != 8 {
      return jwt.NewValidationError(errors.New(`tokens are only valid if issued during August!`))
    }
    return nil
  })

  tok, err := jwt.NewBuilder().
    Issuer(`github.com/lestrrat-go/jwx`).
    IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }

  err = jwt.Validate(tok, jwt.WithValidator(validator))
  if err == nil {
    fmt.Printf("token should fail validation\n")
    return
  }
  fmt.Printf("%s\n", err)
  // OUTPUT:
  // tokens are only valid if issued during August!
}
```
source: [examples/jwt_validate_validator_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_validate_validator_example_test.go)
<!-- END INCLUDE -->

## Detecting error types

If you enable validation during `jwt.Parse()`, you might sometimes want to differentiate between parsing errors and validation errors. To do this, you can use the function `jwt.IsValidationError()`. To further differentiate between specific errors, you can use `errors.Is()`:

<!-- INCLUDE(examples/jwt_validate_detect_error_type_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "errors"
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ValidateDetectErrorType() {
  tok, err := jwt.NewBuilder().
    Issuer(`github.com/lestrrat-go/jwx`).
    Expiration(time.Now().Add(-1 * time.Hour)).
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }

  buf, err := json.Marshal(tok)
  if err != nil {
    fmt.Printf("failed to serialize token: %s\n", err)
    return
  }

  {
    // Case 1: Parsing error. We're not showing verification failure
    // but it is about the same in the context of wanting to know
    // if it's a validation error or not
    _, err := jwt.Parse(buf[:len(buf)-1], jwt.WithVerify(false), jwt.WithValidate(true))
    if err == nil {
      fmt.Printf("token should fail parsing\n")
      return
    }

    if jwt.IsValidationError(err) {
      fmt.Printf("error should NOT be validation error\n")
      return
    }
  }

  {
    // Case 2: Parsing works, validation fails
    // NOTE: This token has NOT been verified for demonstration
    // purposes. Use `jwt.WithKey()` or the like in your production code
    _, err = jwt.Parse(buf, jwt.WithVerify(false), jwt.WithValidate(true))
    if err == nil {
      fmt.Printf("token should fail parsing\n")
      return
    }

    if !jwt.IsValidationError(err) {
      fmt.Printf("error should be validation error\n")
      return
    }

    if !errors.Is(err, jwt.ErrTokenExpired()) {
      fmt.Printf("error should be of token expired type\n")
      return
    }
    fmt.Printf("%s\n", err)
  }
  // OUTPUT:
  // "exp" not satisfied
}
```
source: [examples/jwt_validate_detect_error_type_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_validate_detect_error_type_example_test.go)
<!-- END INCLUDE -->

# JWT Serialization

## Serialize as JSON

`jwt.Token` objects can safely be passed to `"encoding/json".Marshal()` and friends.
In this case it will be marshaled as a JSON object rather than in the compact format.

Since it will be just the raw token, no signing or encryption will be performed.

<!-- INCLUDE(examples/jwt_serialize_json_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"
  "time"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_SerializeJSON() {
  tok, err := jwt.NewBuilder().
    Issuer(`github.com/lestrrat-go/jwx`).
    IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(tok)
  // OUTPUT:
  // {"iat":233431200,"iss":"github.com/lestrrat-go/jwx"}
}
```
source: [examples/jwt_serialize_json_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_serialize_json_example_test.go)
<!-- END INCLUDE -->

## Serialize using JWS

The `jwt` package provides a convenience function `jwt.Sign()` to serialize a token using JWS.

If you need even further customization, consider using the `jws` package directly.

<!-- INCLUDE(examples/jwt_serialize_jws_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_SerializeJWS() {
  tok, err := jwt.NewBuilder().
    Issuer(`github.com/lestrrat-go/jwx`).
    IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }

  rawKey := []byte(`abracadabra`)
  jwkKey, err := jwk.FromRaw(rawKey)
  if err != nil {
    fmt.Printf("failed to create symmetric key: %s\n", err)
    return
  }

  // This example shows you two ways to passing keys to
  // jwt.Sign()
  //
  // * The first key is the "raw" key.
  // * The second one is a jwk.Key that represents the raw key.
  //
  // If this were using RSA/ECDSA keys, you would be using
  // *rsa.PrivateKey/*ecdsa.PrivateKey as the raw key.
  for _, key := range []interface{}{rawKey, jwkKey} {
    serialized, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, key))
    if err != nil {
      fmt.Printf("failed to sign token: %s\n", err)
      return
    }

    fmt.Printf("%s\n", serialized)
  }

  // OUTPUT:
  // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjIzMzQzMTIwMCwiaXNzIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ.K1WVWaM6Dww9aNNFMjnyUfjaaHIs08-3Qb1b8eSEHOk
  // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjIzMzQzMTIwMCwiaXNzIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ.K1WVWaM6Dww9aNNFMjnyUfjaaHIs08-3Qb1b8eSEHOk
}
```
source: [examples/jwt_serialize_jws_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_serialize_jws_example_test.go)
<!-- END INCLUDE -->

## Serialize using JWE and JWS

The `jwt` package provides a `Serializer` object to allow users to serialize a token using an arbitrary combination of processors. 

If for whatever reason the buil-tin `(jwt.Serializer).Sign()` and `(jwt.Serializer).Encrypt()` do not work for you, you may choose to provider a custom serialization step using `(jwt.Serialize).Step()` -- but at this point it may just be easier if you hand-rolled your own serialization.

The following example, encrypts a token using JWE, then uses JWS to sign the encrypted payload:

<!-- INCLUDE(examples/jwt_serialize_jwe_jws_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_SerializeJWEJWS() {
  tok, err := jwt.NewBuilder().
    Issuer(`github.com/lestrrat-go/jwx`).
    IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }

  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to generate private key: %s\n", err)
    return
  }

  enckey, err := jwk.FromRaw(privkey.PublicKey)
  if err != nil {
    fmt.Printf("failed to create symmetric key: %s\n", err)
    return
  }

  signkey, err := jwk.FromRaw([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create symmetric key: %s\n", err)
    return
  }

  serialized, err := jwt.NewSerializer().
    Encrypt(jwt.WithKey(jwa.RSA_OAEP, enckey)).
    Sign(jwt.WithKey(jwa.HS256, signkey)).
    Serialize(tok)
  if err != nil {
    fmt.Printf("failed to encrypt and sign token: %s\n", err)
    return
  }
  _ = serialized
  // We don't use the result of serialization as it will always be
  // different because of randomness used in the encryption logic
  // OUTPUT:
}
```
source: [examples/jwt_serialize_jwe_jws_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_serialize_jwe_jws_example_test.go)
<!-- END INCLUDE -->

## Serialize the the `aud` field as a single string

When you marshal `jwt.Token` into JSON, by default the `aud` field is serialized as an array of strings. This field may take either a single string or array form, but apparently there are parsers that do not understand the array form.

The examples below shoud both be valid, but apparently there are systems that do not understand the former ([AWS Cognito has been reported to be one such system](https://github.com/lestrrat-go/jwx/tree/v2/issues/368)).

```
{
  "aud": ["foo"],
  ...
}
```

```
{
  "aud": "foo",
  ...
}
```

To workaround these problematic parsers, you may use enable the option `jwt.FlattenAudience` on each token that you would like to see this behavior. If you do this for _all_ (or most) tokens, you may opt to change the global default value by settings `jwt.WithFlattenAudience(true)` option via `jwt.Settings()`. 

<!-- INCLUDE(examples/jwt_flatten_audience_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_FlattenAudience() {
  // Sometimes you need to "flatten" the "aud" claim because of
  // parsers developed by people who apparently didn't read the RFC.
  //
  // In such cases, you can control the behavior of the JSON
  // emitted when tokens are converted to JSON by tweaking the
  // per-token options set.

  { // Case 1: the per-object way
    tok, err := jwt.NewBuilder().
      Audience([]string{`foo`}).
      Build()
    if err != nil {
      fmt.Printf("failed to build token: %s\n", err)
      return
    }

    // Only this particular instance of the token is affected
    tok.Options().Enable(jwt.FlattenAudience)
    json.NewEncoder(os.Stdout).Encode(tok)
  }

  { // Case 2: globally enabling flattened audience
    // NOTE: This example DOES NOT flatten the audience
    // because the call to change this global settings has been
    // commented out. Setting this has GLOBAL effects, and would
    // alter the output of other examples.
    //
    // If you would like to try this, UNCOMMENT the line below
    //
    // // UNCOMMENT THIS LINE BELOW
    // jwt.Settings(jwt.WithFlattenAudience(true))
    //
    // ...and if you are running from the examples directory, run
    // this example in isolation by invoking
    //
    //   go test -run=ExampleJWT_FlattenAudience
    //
    // You may see the example fail, but that's because the OUTPUT line
    // expects the global settings to be DISABLED. In order to make
    // the example pass, change the second line from OUTPUT below
    //
    //   from: {"aud":["foo"]}
    //   to  : {"aud":"foo"}
    //
    // Please note that it is recommended you ONLY set the jwt.Settings(jwt.WithFlattenedAudience(true))
    // once at the beginning of your main program (probably in an `init()` function)
    // so that you do not need to worry about causing issues depending
    // on when tokens are created relative to the time when
    // the global setting is changed.

    tok, err := jwt.NewBuilder().
      Audience([]string{`foo`}).
      Build()
    if err != nil {
      fmt.Printf("failed to build token: %s\n", err)
      return
    }

    // This would flatten the "aud" claim if the appropriate
    // line above has been uncommented
    json.NewEncoder(os.Stdout).Encode(tok)

    // This would force this particular object not to flatten the
    // "aud" claim. All other tokens would be constructed with the
    // option enabled
    tok.Options().Enable(jwt.FlattenAudience)
    json.NewEncoder(os.Stdout).Encode(tok)
  }
  // OUTPUT:
  // {"aud":"foo"}
  // {"aud":["foo"]}
  // {"aud":"foo"}
}
```
source: [examples/jwt_flatten_audience_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwt_flatten_audience_example_test.go)
<!-- END INCLUDE -->

# Working with JWT

## Access JWS headers

The RFC defines JWS as an envelope to JWT (JWS can carry any payload, you just happened to assign a JWT to it). A JWT is just a bag of arbitrary key/value pairs, where some of them are predefined for validation. This means that JWS headers are NOT part of a JWT -- and thus you will not be able to access them through the `jwt.Token` itself.

If you need to access these JWS headers while parsing JWS signed JWT, you will need to reach into the tools defined in the `jws` package.

* If you are considering using JWS header fields to decide on which key to use for verification, consider [using a `jwt.KeyProvider`](#parse-and-verify-a-jwt-using-arbitrary-keys).
* If you are looking for ways to 

Please [look at the JWS documentation for it](./02-jws.md#parse-a-jws-message-and-access-jws-headers) .

## Get/Set fields

Any field in the token can be accessed in an uniform away using `(jwt.Token).Get()`

```go
v, ok := token.Get(name)
```

If the field corresponding to `name` does not exist, the second return value will be `false`.

The value `v` is returned as `interface{}`, as there is no way of knowing what the underlying type may be for user defined fields.

For pre-defined fields whose types are known, you can use the convenience methods such as `Subject()`, `Issuer()`, `NotBefore()`, etc.

```go
s := token.Subject()
s := token.Issuer()
t := token.NotBefore()
```

For setting field values, there is only one path, which is to use the `Set()` method. If you are initializing a token you may also [use the builder pattern](#using-builder)

```go
err := token.Set(name, value)
```

For pre-defined fields, `Set()` will return an error when the value cannot be converted to a proper type that suits the specification. For example, fields for time data must be `time.Time` or number of seconds since epoch. See the `jwt.Token` interface and the getter methods for these fields to learn about the types for pre-defined fields.
