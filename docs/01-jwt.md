# Working with JWT

In this document we describe how to work with JWT using `github.com/lestrrat-go/jwx/v4/jwt`

- [Terminology](#terminology)
  - [Verification](#verification)
  - [Validation](#validation)
- [Parsing](#parsing)
  - [Parse a JWT](#parse-a-jwt)
  - [Parse a JWT from file](#parse-a-jwt-from-file)
  - [Parse a JWT from a \*http.Request](#parse-a-jwt-from-a-httprequest)
- [Programmatically Creating a JWT](#programmatically-creating-a-jwt)
  - [Using jwt.New](#using-jwtnew)
  - [Using Builder](#using-builder)
- [Verification](#jwt-verification)
  - [Parse and Verify a JWT (with a single key)](#parse-and-verify-a-jwt-with-single-key)
  - [Parse and Verify a JWT (with a key set, matching `kid`)](#parse-and-verify-a-jwt-with-a-key-set-matching-kid)
  - [Parse and Verify a JWT (using arbitrary keys)](#parse-and-verify-a-jwt-using-arbitrary-keys)
  - [Parse and Verify a JWT (using key specified in `jku`)](#parse-and-verify-a-jwt-using-key-specified-in-jku)
- [Validation](#jwt-validation)
  - [Validate for specific claim values](#validate-for-specific-claim-values)
  - [Use a custom validator](#use-a-custom-validator)
  - [Detecting error types](#detecting-error-types)
  - [Replay protection (jti)](#replay-protection-jti)
- [Filtering Claims](#filtering-claims)
  - [Filtering Using Standard Claim Names](#filtering-using-standard-claim-names)
  - [Advanced filtering scenarios](#advanced-filtering-scenarios)
- [Serialization](#serialization)
  - [Serialize using JWS](#serialize-using-jws)
  - [Serialize using JWE and JWS](#serialize-using-jwe-and-jws)
  - [Serialize the `aud` field as a single string](#serialize-the-aud-field-as-a-single-string)
- [Working with JWT](#working-with-jwt-1)
  - [Performance](#performance)
  - [Access JWS headers](#access-jws-headers)
  - [Get/Set fields](#getset-fields)
  - [Using a custom base64 encoder](#using-a-custom-base64-encoder)

---

# Terminology

## Verification

We use the terms "verify" and "verification" to describe the process of ensuring the integrity of the JWT, namely the signature verification.

## Validation

We use the terms "validate" and "validation" to describe the process of checking the contents of a JWT, for example if the values in fields such as "iss", "sub", "aud" match our expected values, and/or if the token has expired.

# Parsing

Parsing a payload as JWT consists of multiple distinct operations. Typically, your JWTs are signed and serialized as JWS messages. The JWT is _enveloped_ in JWS. The following is a [sample JWS message serialized in compact form](https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1):

```
eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX
```

This message consists of three data segments encoded in `base64`, concatenated with a `.`. Each part reads as follows:

- **Part 1**: The JWS protected headers. These are metadata required to verify the signed payload.
- **Part 2**: The JWS payload. This can be any arbitrary data, but in our case it would be a JWT object.
- **Part 3**: The JWS signature. This is the signature generated from the signing key, the headers, and the payload.

It is important to realize that JWS in itself has nothing to do with JWT. The envelope and therefore the JWS mechanism itself does not care that the payload is JWT or not.

Once we verify the integrity of the payload using JWS verification, the payload can then be trusted to be untampered.
Therefore, while the JWS payload _could_ theoretically be decoded as a JWT object before verification, its contents
should not be trusted -- e.g. it should not be used to store information that has to do with verification.

The `jwt.Parse()` function in this package not only provides ways to decode a JWT object from JSON, but it also
provides convenient ways to perform the above verification and decoding of the JWT object in one go,
as well as validating the contents of the JWT object after it has been decoded.

## Parse a JWT

To parse a JWT in either raw JSON or JWS compact serialization format, use [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#Parse)

<!-- INCLUDE(examples/jwt_parse_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_parse() {
  tok, err := jwt.Parse(jwtSignedWithHS256, jwt.WithKey(jwa.HS256(), jwkSymmetricKey))
  if err != nil {
    fmt.Printf("%s\n", err)
    return
  }
  _ = tok
  // OUTPUT:
}
```
source: [examples/jwt_parse_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_parse_example_test.go)
<!-- END INCLUDE -->

Note that the above form performs only signature verification and no validation of the JWT token itself.
In order to perform validation, please use `Validate()`.

## Parse a JWT from a filesystem

To parse a JWT stored in a file, use [`jwt.ParseFS()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#ParseFS). [`jwt.ParseFS()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#ParseFS) accepts the same options as [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#Parse).

<!-- INCLUDE(examples/jwt_parsefs_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "os"
  "path/filepath"

  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_ParseFS() {
  f, err := os.CreateTemp(``, `jwt_parsefs-*.jws`)
  if err != nil {
    fmt.Printf("failed to create temporary file: %s\n", err)
    return
  }
  defer os.Remove(f.Name())

  fmt.Fprint(f, exampleJWTSignedHMAC)
  f.Close()

  // This example calls ParseFS with both jwt.WithVerify(false) and
  // jwt.WithValidate(false) only because there is no key context
  // here — it demonstrates the FS-loading mechanics, nothing more.
  // Production code reading a JWT from any source MUST pass
  // jwt.WithKey() / jwt.WithKeySet() and MUST NOT disable
  // jwt.WithValidate. The library exposes jwt.ParseInsecure for the
  // inspect-without-verifying path when consuming raw bytes
  // directly; ParseFS has no corresponding ParseFSInsecure today,
  // so the two-option chant is the explicit way to express the
  // same intent here.
  tok, err := jwt.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()), jwt.WithVerify(false), jwt.WithValidate(false))
  if err != nil {
    fmt.Printf("failed to read file %q: %s\n", f.Name(), err)
    return
  }
  _ = tok
  // OUTPUT:
}
```
source: [examples/jwt_parsefs_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_parsefs_example_test.go)
<!-- END INCLUDE -->

## Parse a JWT from a \*http.Request

To parse a JWT stored within a \*http.Request object, use [`jwt.ParseRequest()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#ParseRequest). It by default looks for JWTs stored in the "Authorization" header, but can be configured to look under other headers and within the form fields.

<!-- INCLUDE(examples/jwt_parse_request_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "net/http"
  "net/url"

  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_parse_request_authorization() {
  req, err := http.NewRequest(http.MethodGet, `https://github.com/lestrrat-go/jwx`, nil)
  if err != nil {
    fmt.Printf("failed to create request: %s\n", err)
    return
  }
  req.Form = url.Values{}
  req.Form.Add("access_token", exampleJWTSignedHMAC)

  req.Header.Set(`Authorization`, fmt.Sprintf(`Bearer %s`, exampleJWTSignedECDSA))
  req.Header.Set(`X-JWT-Token`, exampleJWTSignedRSA)

  req.AddCookie(&http.Cookie{Name: "accessToken", Value: exampleJWTSignedHMAC})

  var dst *http.Cookie

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
    // Looks under "accessToken" cookie, and assigns the http.Cookie object
    // where the token came from to the variable `dst`
    {
      options: []jwt.ParseOption{jwt.WithCookieKey(`accessToken`), jwt.WithCookie(&dst)},
    },
  }

  for _, tc := range testcases {
    // jwt.WithVerify(false) + jwt.WithValidate(false) below is only
    // because this example has no key context — it demonstrates
    // where ParseRequest looks for a token, nothing more.
    // Production code MUST pass jwt.WithKey() / jwt.WithKeySet()
    // and MUST NOT disable jwt.WithValidate. (ParseRequest has no
    // ParseRequestInsecure variant; jwt.ParseInsecure exists for
    // the raw-bytes path when you genuinely just want to inspect.)
    options := append(tc.options, []jwt.ParseOption{jwt.WithVerify(false), jwt.WithValidate(false)}...)
    tok, err := jwt.ParseRequest(req, options...)
    if err != nil {
      fmt.Print("jwt.ParseRequest with options [")
      for i, option := range tc.options {
        if i > 0 {
          fmt.Print(", ")
        }
        fmt.Printf("%s", option)
      }
      fmt.Printf("]: %s\n", err)
      return
    }
    _ = tok
  }

  if dst == nil {
    fmt.Printf("failed to assign cookie to dst\n")
    return
  }
  // OUTPUT:
}
```
source: [examples/jwt_parse_request_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_parse_request_example_test.go)
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

  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_construct() {
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
source: [examples/jwt_construct_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_construct_example_test.go)
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

  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_builder() {
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
source: [examples/jwt_builder_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_builder_example_test.go)
<!-- END INCLUDE -->

# JWT Verification

## Parse and Verify a JWT (with single key)

To parse a JWT _and_ verify that its content matches the signature as described in the JWS message, you need to add some options when calling the [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#Parse) function.

<!-- INCLUDE(examples/jwt_parse_with_key_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_parse_with_key() {
  // Parse a symmetric JWK that will be used both to sign and to verify
  // the token. In a real deployment the signing key lives on the issuer
  // and only the verifier side sees the key material — we do both here
  // so the example is self-contained.
  const keysrc = `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`
  key, err := jwk.ParseKey([]byte(keysrc))
  if err != nil {
    fmt.Printf("jwk.ParseKey failed: %s\n", err)
    return
  }

  // Build a fresh token with a future `exp` so the example can exercise
  // the full verification + validation path. Using a canned RFC-era
  // fixture here would force us to disable validation, which is exactly
  // the footgun this example is meant to avoid teaching.
  tok, err := jwt.NewBuilder().
    Issuer(`github.com/lestrrat-go/jwx`).
    IssuedAt(time.Now()).
    Expiration(time.Now().Add(time.Hour)).
    Build()
  if err != nil {
    fmt.Printf("jwt.NewBuilder failed: %s\n", err)
    return
  }

  // Sign with HS256. `jwt.WithKey` binds the algorithm to the key at
  // sign time — the signed token's protected header will carry `alg:HS256`.
  signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
  if err != nil {
    fmt.Printf("jwt.Sign failed: %s\n", err)
    return
  }

  // Parse + verify + validate in one call. Passing `jwa.HS256()`
  // explicitly to `jwt.WithKey` is the alg-confusion defense: the
  // verifier will reject the token unless its protected header matches
  // this algorithm, so an attacker cannot swap in a token signed with a
  // different algorithm that happens to accept the same key bytes.
  //
  // `jwt.Parse` runs claim validation (`exp`, `nbf`, `iat`) by default.
  // Do NOT pass `jwt.WithValidate(false)` in production code — doing so
  // accepts expired or not-yet-valid tokens.
  parsed, err := jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
  if err != nil {
    fmt.Printf("jwt.Parse failed: %s\n", err)
    return
  }

  iss, _ := parsed.Issuer()
  fmt.Printf("issuer: %s\n", iss)
  // OUTPUT:
  // issuer: github.com/lestrrat-go/jwx
}
```
source: [examples/jwt_parse_with_key_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_parse_with_key_example_test.go)
<!-- END INCLUDE -->

In the above example, `key` may either be the raw key (i.e. "crypto/ecdsa".PublicKey, "crypto/ecdsa".PrivateKey) or an instance of [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Key) (i.e. [`jwk.ECDSAPrivateKey`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#ECDSAPrivateKey), [`jwk.ECDSAPublicKey`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#ECDSAPublicKey)). The key type must match the algorithm being used.

## Parse and Verify a JWT (with a key set, matching `kid`)

To parse a JWT _and_ verify that its content matches the signature as described in the JWS message using a [`jwk.Set`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Set), you need to add some options when calling the [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#Parse) function.

The following code does a lot of preparation to mimic a real JWKS signed JWT, but the code required in the user side is located towards the end.

In real life, the location of JWKS files are specified by the service that provided you with the signed JWT. The URL for these JWKS files often (but are not always guaranteed to be) take the form `https://DOMAIN/.well-known/jwks.json` and the like. If you need to fetch these in your code, [refer to the documentation on `jwk` package](04-jwk.md#fetching-jwk-sets).

<!-- INCLUDE(examples/jwt_parse_with_keyset_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_parse_with_key_set() {
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
    realKey, err := jwk.Import[jwk.Key](privKey)
    if err != nil {
      fmt.Printf("failed to create JWK: %s\n", err)
      return
    }
    realKey.Set(jwk.KeyIDKey, `mykey`)
    realKey.Set(jwk.AlgorithmKey, jwa.RS256())

    // For demonstration purposes, we also create a second RSA key that
    // should not match the token. Public JWKS helpers now reject
    // symmetric keys because they have no safe public representation.
    bogusPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
      fmt.Printf("failed to generate bogus private key: %s\n", err)
      return
    }
    bogusKey, err := jwk.Import[jwk.Key](bogusPrivKey)
    if err != nil {
      fmt.Printf("failed to create bogus JWK: %s\n", err)
      return
    }
    bogusKey.Set(jwk.AlgorithmKey, jwa.RS256())
    bogusKey.Set(jwk.KeyIDKey, "otherkey")

    // Now create a key set that users will use to verity the signed serialized against
    // Normally these keys are available somewhere like https://www.googleapis.com/oauth2/v3/certs
    // This key set contains two keys, the first one is the correct one

    // We can use the jwk.PublicSetOf() utility to get a JWKS of the public keys
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
  signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), signingKey))
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
source: [examples/jwt_parse_with_keyset_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_parse_with_keyset_example_test.go)
<!-- END INCLUDE -->

There are a couple of things to note.

First is that the signing key is initialized with key ID (`kid`). By using a `jwk.Key` with `kid` field set,
the resulting JWS message will also have the field `kid` set to the same value in the
corresponding protected headers. This is set because the default behavior is to ONLY accept
keys if they have matching `kid` fields in the JWS protected headers.

You may override this behavior if you explicitly specify to turn this off using
the `jws.WithRequireKid(false)` option, but this is not recommended. If you already
know which is supposed to work beforehand, it is recommended that you parse the `jwk.Set`
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
  "encoding/base64"
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jws"
  "github.com/lestrrat-go/jwx/v4/jws/jwsbb"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_parse_with_key_provider_use_token() {
  // This example shows how one might use the information in the JWT to
  // load different keys.

  // Setup
  origIssuer := "me"
  tok, err := jwt.NewBuilder().
    Issuer(origIssuer).
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }

  symmetricKey := []byte("Abracadabra")
  alg := jwa.HS256()
  signed, err := jwt.Sign(tok, jwt.WithKey(alg, symmetricKey))
  if err != nil {
    fmt.Printf("failed to sign token: %s\n", err)
    return
  }

  // This next example assumes that you want to minimize the number of
  // times you parse the JWT JSON
  {
    _, b64payload, _, err := jwsbb.SplitCompact(signed)
    if err != nil {
      fmt.Printf("failed to split jws: %s\n", err)
      return
    }

    enc := base64.RawStdEncoding
    payload := make([]byte, enc.DecodedLen(len(b64payload)))
    _, err = enc.Decode(payload, b64payload)
    if err != nil {
      fmt.Printf("failed to decode base64 payload: %s\n", err)
      return
    }

    parsed, err := jwt.Parse(payload, jwt.WithVerify(false))
    if err != nil {
      fmt.Printf("failed to parse JWT: %s\n", err)
      return
    }

    _, err = jws.Verify(signed, jws.WithKeyProvider(jws.KeyProviderFunc(func(_ context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
      // `iss` came from `parsed`, which was produced by
      // jwt.Parse(... jwt.WithVerify(false)). It is
      // UNVERIFIED, caller-controlled input. The only safe
      // way to use it here is as a lookup key against a
      // closed allowlist of trusted issuers — exactly the
      // switch below. Never use `iss` as a filesystem path,
      // URL, cache key, or any other unbounded input: a
      // malicious sender controls the string and will gladly
      // inject `..`, NUL bytes, control characters, or
      // anything else. The jws.Verify call this provider
      // feeds into is what gates trust; before that, claims
      // from `parsed` are just bytes off the wire.
      iss, ok := parsed.Issuer()
      if !ok {
        return fmt.Errorf("no issuer found")
      }
      switch iss {
      case "me":
        sink.Key(alg, symmetricKey)
        return nil
      default:
        return fmt.Errorf("unknown issuer %q", iss)
      }
    })))

    if err != nil {
      fmt.Printf("%s\n", err)
      return
    }

    if iss, ok := parsed.Issuer(); !ok || iss != origIssuer {
      fmt.Printf("issuers do not match\n")
      return
    }
  }

  // OUTPUT:
  //
}

func Example_jwt_parse_with_key_provider() {
  // Pretend that this is a storage somewhere (maybe a database) that maps
  // a signature algorithm to a key
  store := make(map[jwa.KeyAlgorithm]any)
  algorithms := []jwa.SignatureAlgorithm{
    jwa.RS256(),
    jwa.RS384(),
    jwa.RS512(),
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
    alg, ok := sig.ProtectedHeaders().Algorithm()
    if !ok {
      return nil
    }
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
source: [examples/jwt_parse_with_key_provider_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_parse_with_key_provider_example_test.go)
<!-- END INCLUDE -->

## Parse and Verify a JWT (using key specified in `jku`)

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

  "github.com/jwx-go/jwkfetch/v4"
  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_parse_with_jku() {
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
    privkey, err := jwk.Import[jwk.Key](pk)
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

  serialized, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), signingKey, jws.WithProtectedHeaders(hdrs)))
  if err != nil {
    fmt.Printf("failed to seign token: %s\n", err)
    return
  }

  // jku verification uses a jwk.Fetcher to retrieve the JWKS
  // referenced in the JWS protected header. Use jwkfetch.Client —
  // it is the canonical implementation and the one this option is
  // designed around.
  //
  // IMPORTANT: the `jku` URL comes from the JWS protected header,
  // which is untrusted input. A real application MUST pass
  // jwkfetch.WithWhitelist with a MapWhitelist / RegexpWhitelist
  // restricted to its known issuer set — otherwise a hostile peer
  // can point the fetcher at any URL it can reach (SSRF) and have
  // its own keys accepted as "the issuer's keys". This example uses
  // srv.URL as a "known issuer" because httptest picks a random
  // port each run.
  client := jwkfetch.NewClient(
    // httptest serves HTTPS with a self-signed cert, so the
    // Client needs srv.Client() to validate it.
    jwkfetch.WithHTTPClient(srv.Client()),
    jwkfetch.WithWhitelist(jwkfetch.NewMapWhitelist().Add(srv.URL)),
  )
  tok, err := jwt.Parse(serialized, jwt.WithVerifyAuto(client))
  if err != nil {
    fmt.Printf("failed to verify token: %s\n", err)
    return
  }
  _ = tok
  // OUTPUT:
}
```
source: [examples/jwt_parse_with_jku_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_parse_with_jku_example_test.go)
<!-- END INCLUDE -->

This feature must be used with extreme caution. Please see the caveats and fine prints
in the documentation for `jws.VerifyAuto()`

# JWT Validation

To validate if the JWT's contents, such as if the JWT contains the proper "iss","sub","aut", etc, or the expiration information and such, use the [`jwt.Validate()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#Validate) function.

<!-- INCLUDE(examples/jwt_validate_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_validate() {
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
  // jwt.Validate: validation failed: "exp" not satisfied: token is expired
  // jwt.Parse: failed to parse token: jwt.Validate: validation failed: "exp" not satisfied: token is expired
}
```
source: [examples/jwt_validate_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_validate_example_test.go)
<!-- END INCLUDE -->

## Validate for specific claim values

By default we only check for the time-related components of a token, such as "iat", "exp", and "nbf". To tell [`jwt.Validate()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#Validate) to check for other fields, use one of the various [`jwt.ValidateOption`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#ValidateOption) values, such as `jwt.WithClaimValue()`, `jwt.WithRequiredClaim()`, etc.

<!-- INCLUDE(examples/jwt_validate_issuer_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_validate_issuer() {
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
  // jwt.Validate: validation failed: "iss" not satisfied: claim "iss" does not have the expected value
}
```
source: [examples/jwt_validate_issuer_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_validate_issuer_example_test.go)
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

  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_validate_validator() {
  validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) error {
    iat, ok := t.IssuedAt()
    if !ok {
      return errors.New(`token does not have "iat" claim`)
    }
    if iat.Month() != 8 {
      return errors.New(`tokens are only valid if issued during August!`)
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
  // jwt.Validate: validation failed: tokens are only valid if issued during August!
}
```
source: [examples/jwt_validate_validator_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_validate_validator_example_test.go)
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

  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_validate_detect_error_type() {
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
    // Case 1: Parsing error. We're not showing verification failure,
    // but it is about the same in the context of wanting to know
    // if it's a validation error or not
    _, err := jwt.Parse(buf[:len(buf)-1], jwt.WithVerify(false), jwt.WithValidate(true))
    if err == nil {
      fmt.Printf("token should fail parsing\n")
      return
    }

    if errors.Is(err, jwt.ValidationError{}) {
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

    if !errors.Is(err, jwt.ValidationError{}) {
      fmt.Printf("error should be validation error\n")
      return
    }

    if !errors.Is(err, jwt.TokenExpiredError{}) {
      fmt.Printf("error should be of token expired type\n")
      return
    }

    fmt.Printf("%s\n", err)
  }
  // OUTPUT:
  // jwt.Parse: failed to parse token: jwt.Validate: validation failed: "exp" not satisfied: token is expired
}
```
source: [examples/jwt_validate_detect_error_type_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_validate_detect_error_type_example_test.go)
<!-- END INCLUDE -->

## Replay protection (jti)

The `jti` (JWT ID) claim provides a unique identifier for a token. While this library supports reading and validating the `jti` claim value, it does **not** provide built-in replay protection — that is, it does not track previously seen `jti` values or reject reused tokens.

This is by design: the JWT specification (RFC 7519 Section 4.1.7) defines `jti` as a means to prevent the JWT from being replayed, but leaves the implementation of such tracking to the application. A replay cache requires application-specific decisions about storage backend, token lifetime, and distributed coordination that are outside the scope of a JWT library.

### What the library provides

You can validate that a token's `jti` matches an expected value using `jwt.WithJwtID()`:

```go
err := jwt.Validate(tok, jwt.WithJwtID("expected-unique-id"))
```

You can also require the `jti` claim to be present using `jwt.WithRequiredClaim()`:

```go
err := jwt.Validate(tok, jwt.WithRequiredClaim(jwt.JwtIDKey))
```

### What callers must implement

To prevent token replay, callers should:

1. **Generate unique `jti` values** when issuing tokens (e.g., using UUIDs)
2. **Track seen `jti` values** in a store appropriate for the deployment (in-memory, Redis, database, etc.)
3. **Reject tokens with previously seen `jti` values**, typically using a custom validator:

```go
validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) error {
    jti, ok := t.JwtID()
    if !ok {
        return jwt.NewValidationError(fmt.Errorf(`"jti" claim is required`))
    }
    if replayCache.HasSeen(jti) {
        return jwt.NewValidationError(fmt.Errorf(`token with jti %q has already been used`, jti))
    }
    replayCache.MarkSeen(jti, t.Expiration())
    return nil
})

err := jwt.Validate(tok, jwt.WithValidator(validator))
```

4. **Expire cache entries** when the corresponding token's `exp` time passes, to bound cache growth

# Filtering Claims

JWT tokens can contain many different types of claims - standard claims like `iss`, `aud`, `exp`, as well as custom application-specific claims. Sometimes you need to create modified versions of tokens that only contain certain claims, either for security purposes, API compatibility, or to create specialized token types.

While [`jwt.Token`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#Token) object itself does not offer ways to directly extract out these claims, you can use the [`jwt.TokenFilter`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#TokenFilter) interface provides methods to filter JWT claims in a flexible way.

## Filtering Using Standard Claim Names

The most common way to filter claims is by either excluding or including only the standard JWT claims. 

For convenience, this library provides `jwt.StandardClaimsFilter()` which filters standard JWT claims defined in RFC 7519.  You can either use `(filter).Filter(token)` to create a `jwt.Token` that contains only the standard claims, or use `(filter).Reject(token)` to create a `jwt.Token` that contains only non-standard claims.

<!-- INCLUDE(examples/jwt_filter_basic_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "time"

  "github.com/jwx-go/jwxfilter/v4/jwtfilter"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_filter_basic_claims() {
  // Create a token with standard and custom claims.
  token, err := jwt.NewBuilder().
    Issuer("github.com/lestrrat-go/jwx").
    Subject("jwt_filter_example").
    Audience([]string{"developers", "users"}).
    IssuedAt(time.Unix(1234567890, 0)).
    Expiration(time.Unix(1234567890+3600, 0)).
    Claim("customClaim", "customValue").
    Claim("applicationRole", "admin").
    Claim("department", "engineering").
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }

  // Filters live in the companion module github.com/jwx-go/jwxfilter/v4.
  // They were moved out of core in v4 because sign / verify / parse do
  // not depend on them. jwtfilter.ByName builds a filter that matches
  // the specified claim names; the returned jwxfilter.Filter[jwt.Token]
  // has Filter(token) and Reject(token) methods.
  customFilter := jwtfilter.ByName("customClaim", "applicationRole", "department")

  // Filter returns a fresh token containing only the matching claims.
  if _, err := customFilter.Filter(token); err != nil {
    fmt.Printf("failed to filter custom claims: %s\n", err)
    return
  }
  // Reject returns a fresh token with the matching claims removed.
  if _, err := customFilter.Reject(token); err != nil {
    fmt.Printf("failed to reject custom claims: %s\n", err)
    return
  }

  // jwtfilter.Standard() is a preset filter targeting the seven RFC 7519
  // claims (aud, exp, iat, iss, jti, nbf, sub). Filter keeps only them;
  // Reject keeps only non-standard (custom) claims.
  if _, err = jwtfilter.Standard().Filter(token); err != nil {
    fmt.Printf("failed to filter standard claims: %s\n", err)
    return
  }

  if _, err = jwtfilter.Standard().Reject(token); err != nil {
    fmt.Printf("failed to reject standard claims: %s\n", err)
    return
  }

  // OUTPUT:
}
```
source: [examples/jwt_filter_basic_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_filter_basic_example_test.go)
<!-- END INCLUDE -->

For OpenID tokens, you could also use `openid.StandardClaimsFilter()`.

## Advanced filtering scenarios

If you want to control what gets filtered, you can create a [`jwt.TokenFilter`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#TokenFilter) of your own. If all you want to do is filter by claim names, you can re-use the existing `jwt.ClaimNameFilter`. If you want you can also combine multiple filters to create sophisticated filtering logic.

<!-- INCLUDE(examples/jwt_filter_advanced_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "time"

  "github.com/jwx-go/jwxfilter/v4/jwtfilter"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_filter_advanced_use_cases() {
  // Create a comprehensive token with various types of claims.
  token, err := jwt.NewBuilder().
    Issuer("auth-service.example.com").
    Subject("user-456").
    Audience([]string{"web-app", "mobile-app", "api-gateway"}).
    IssuedAt(time.Unix(1234567890, 0)).
    Expiration(time.Unix(1234567890+7200, 0)).
    NotBefore(time.Unix(1234567890, 0)).
    JwtID("session-xyz789").
    Claim("userRole", "manager").
    Claim("department", "sales").
    Claim("permissions", []string{"read:reports", "write:orders", "approve:discounts"}).
    Claim("profile", map[string]any{
      "name":  "John Doe",
      "email": "john@example.com",
      "phone": "+1-555-0123",
    }).
    Claim("sessionInfo", map[string]any{
      "loginIP":      "10.0.1.100",
      "deviceType":   "desktop",
      "browser":      "Chrome/91.0",
      "lastActivity": "2023-01-01T12:30:00Z",
    }).
    Claim("features", []string{"beta-ui", "advanced-analytics", "mobile-push"}).
    Build()
  if err != nil {
    fmt.Printf("failed to build comprehensive token: %s\n", err)
    return
  }

  // Use case 1: scrub sensitive fields before handing the token to a
  // public-facing API. jwtfilter.ByName builds a filter that matches
  // the specified claim names; Reject returns a copy with those claims
  // removed.
  sensitiveFilter := jwtfilter.ByName("sessionInfo", "profile")
  if _, err := sensitiveFilter.Reject(token); err != nil {
    fmt.Printf("failed to create public API token: %s\n", err)
    return
  }

  // Use case 2: keep only identity-oriented claims. Filter (as opposed
  // to Reject) keeps the matched names.
  identityFilter := jwtfilter.ByName("sub", "iss", "userRole", "department")
  if _, err := identityFilter.Filter(token); err != nil {
    fmt.Printf("failed to create identity token: %s\n", err)
    return
  }

  // Use case 3: keep only the standard security / time claims. Callers
  // who want exactly the RFC 7519 set can use jwtfilter.Standard()
  // instead of enumerating by name; spelling them out here is shown for
  // illustration.
  securityFilter := jwtfilter.ByName("iss", "sub", "aud", "exp", "iat", "nbf", "jti")
  if _, err := securityFilter.Filter(token); err != nil {
    fmt.Printf("failed to create security token: %s\n", err)
    return
  }

  // Use case 4: compose filters. First strip every RFC 7519 claim, then
  // strip two specific custom ones. Each Filter/Reject call returns a
  // fresh jwt.Token, so chaining is just sequential application.
  tempToken, err := jwtfilter.Standard().Reject(token)
  if err != nil {
    fmt.Printf("failed to remove standard claims: %s\n", err)
    return
  }

  customSensitiveFilter := jwtfilter.ByName("sessionInfo", "profile")
  if _, err := customSensitiveFilter.Reject(tempToken); err != nil {
    fmt.Printf("failed to remove custom sensitive claims: %s\n", err)
    return
  }

  // OUTPUT:
}
```
source: [examples/jwt_filter_advanced_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_filter_advanced_example_test.go)
<!-- END INCLUDE -->

# Serialization

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

  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_serialize_json() {
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
source: [examples/jwt_serialize_json_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_serialize_json_example_test.go)
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

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_serialize_jws() {
  tok, err := jwt.NewBuilder().
    Issuer(`github.com/lestrrat-go/jwx`).
    IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
    Build()
  if err != nil {
    fmt.Printf("failed to build token: %s\n", err)
    return
  }

  rawKey := []byte(`abracadabra`)
  jwkKey, err := jwk.Import[jwk.Key](rawKey)
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
  for _, key := range []any{rawKey, jwkKey} {
    serialized, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
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
source: [examples/jwt_serialize_jws_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_serialize_jws_example_test.go)
<!-- END INCLUDE -->

> Warning: the symmetric literals in these examples are deliberately short for readability. Production `HS*` keys should be random secrets that meet the minimum sizes described in [the JWK docs](04-jwk.md).

## Serialize using JWE and JWS

The `jwt` package provides a `Serializer` object to allow users to serialize a token using an arbitrary combination of processors.

If for whatever reason the built-in `(jwt.Serializer).Sign()` and `(jwt.Serializer).Encrypt()` do not work for you, you may choose to provider a custom serialization step using `(jwt.Serialize).Step()` -- but at this point it may just be easier if you hand-rolled your own serialization.

The following example, encrypts a token using JWE, then uses JWS to sign the encrypted payload:

<!-- INCLUDE(examples/jwt_serialize_jwe_jws_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_serialize_jwe_jws() {
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

  enckey, err := jwk.Import[jwk.Key](privkey.PublicKey)
  if err != nil {
    fmt.Printf("failed to create symmetric key: %s\n", err)
    return
  }

  signkey, err := jwk.Import[jwk.Key]([]byte(`abracadabra`))
  if err != nil {
    fmt.Printf("failed to create symmetric key: %s\n", err)
    return
  }

  serialized, err := jwt.NewSerializer().
    Encrypt(jwt.WithKey(jwa.RSA_OAEP_256(), enckey)).
    Sign(jwt.WithKey(jwa.HS256(), signkey)).
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
source: [examples/jwt_serialize_jwe_jws_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_serialize_jwe_jws_example_test.go)
<!-- END INCLUDE -->

## Serialize the `aud` field as a single string

When you marshal `jwt.Token` into JSON, by default the `aud` field is serialized as an array of strings. This field may take either a single string or array form, but apparently there are parsers that do not understand the array form.

The examples below should both be valid, but apparently there are systems that do not understand the former ([AWS Cognito has been reported to be one such system](https://github.com/lestrrat-go/jwx/issues/368)).

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

To work around these problematic parsers, you may use enable the option `jwt.FlattenAudience` on each token that you would like to see this behavior. If you do this for _all_ (or most) tokens, you may opt to change the global default value by settings `jwt.WithFlattenAudience(true)` option via `jwt.Settings()`.

<!-- INCLUDE(examples/jwt_flatten_audience_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_flatten_Audience() {
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
source: [examples/jwt_flatten_audience_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_flatten_audience_example_test.go)
<!-- END INCLUDE -->

# Working with JWT

## Performance

github.com/lestrrat-go/jwx is focused on usability / stable API. If you are worried about performance while processing JWTs, the best path is just to use a plain struct after handling JWS yourself:

<!-- INCLUDE(examples/jwt_raw_struct_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jws"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_plain_struct() {
  t1, err := jwt.NewBuilder().
    Issuer("https://github.com/lestrrat-go/jwx/v4/examples").
    Subject("raw_struct").
    Claim("private", "foobar").
    Build()
  if err != nil {
    fmt.Fprintf(os.Stderr, "failed to build JWT: %s\n", err)
  }

  key := []byte("secret")
  signed, err := jwt.Sign(t1, jwt.WithKey(jwa.HS256(), key))
  if err != nil {
    fmt.Printf("failed to sign JWT: %s\n", err)
  }

  rawJWT, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
  if err != nil {
    fmt.Printf("failed to verify JWS: %s\n", err)
  }

  type MyToken struct {
    Issuer  string `json:"iss"`
    Subject string `json:"sub"`
    Private string `json:"private"`
  }

  var t2 MyToken
  if err := json.Unmarshal(rawJWT, &t2); err != nil {
    fmt.Printf("failed to unmarshal JWT: %s\n", err)
  }

  fmt.Printf("%s\n", t2.Private)
  // OUTPUT:
  // foobar
}
```
source: [examples/jwt_raw_struct_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_raw_struct_example_test.go)
<!-- END INCLUDE -->

This makes sure that you do not go through any extra layers of abstraction that causes performance penalties, and you get exactly the type of field that you want.

## Access JWS headers

The RFC defines JWS as an envelope to JWT (JWS can carry any payload, you just happened to assign a JWT to it). A JWT is just a bag of arbitrary key/value pairs, where some of them are predefined for validation. This means that JWS headers are NOT part of a JWT -- and thus you will not be able to access them through the `jwt.Token` itself.

If you need to access these JWS headers while parsing JWS signed JWT, you will need to reach into the tools defined in the `jws` package.

- If you are considering using JWS header fields to decide on which key to use for verification, consider [using a `jwt.KeyProvider`](#parse-and-verify-a-jwt-using-arbitrary-keys).
- If you are looking for ways to

Please [look at the JWS documentation for it](./02-jws.md#parse-a-jws-message-and-access-jws-headers) .

## Get/Set fields

Any field in the token can be accessed in a uniform away using `(jwt.Token).Get()`

```go
var v interface{} // can be concrete type, if you know the type beforehand
err := token.Get(name, &v)
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

## Using a custom base64 encoder

Per specification JWT should be using URL base64 encoding with no padding when generating (and by nature of the process when verifying as well) signatures. However, some systems do not necessarily adhere to the standards ([there have been reports that AWS ALB is one such system, generating User Claims JWT with padding](https://github.com/lestrrat-go/jwx/discussions/1324))

In these situations, you will need to specify the base64 encoder to your `jwt.Sign` and `jwt.Parse` calls.

<!-- INCLUDE(examples/jwt_sign_with_custom_base64_example_test.go) -->
```go
package examples_test

import (
  "encoding/base64"
  "encoding/json"
  "fmt"
  "os"
  "time"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_sign_with_custom_base64_encoder() {
  const symmetricKey = "0123456789abcdef0123456789abcdef"

  token, err := jwt.NewBuilder().
    Subject("github.com/lestrrat-go/jwx").
    IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
    Build()
  if err != nil {
    fmt.Printf("failed to create token: %s\n", err)
    return
  }

  signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), []byte(symmetricKey)), jwt.WithBase64Encoder(base64.URLEncoding))
  if err != nil {
    fmt.Printf("failed to sign token: %s\n", err)
    return
  }

  fmt.Println(string(signed))

  parsed, err := jwt.Parse(signed, jwt.WithKey(jwa.HS256(), []byte(symmetricKey)), jwt.WithBase64Encoder(base64.URLEncoding))
  if err != nil {
    fmt.Printf("failed to parse token: %s\n", err)
    return
  }

  if err := json.NewEncoder(os.Stdout).Encode(parsed); err != nil {
    fmt.Printf("failed to encode token: %s\n", err)
    return
  }

  if !jwt.Equal(token, parsed) {
    fmt.Printf("parsed token does not match original token\n")
    return
  }

  // OUTPUT:
  // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjIzMzQzMTIwMCwic3ViIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ==.qZu-ATTtmo9k1NedYgwwBzaEYEJA1Z6dlVzPpmzrrrw=
  // {"iat":233431200,"sub":"github.com/lestrrat-go/jwx"}
}
```
source: [examples/jwt_sign_with_custom_base64_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwt_sign_with_custom_base64_example_test.go)
<!-- END INCLUDE -->

You can use these option for `jws.Sign` and `jws.Verify` as well. See the [JWS docs for an example](./02-jwt.md#using-a-custom-base64-encoder).
