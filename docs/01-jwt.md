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
  * [Parse and Verify a JWT (using key specified in "jku")](#parse-and-verify-a-jwt-using-key-specified-in-jku)
  * [Parse and Verify a JWT (using custom key retrieval logic)](#parse-and-verify-a-jwt-using-custom-key-retrieval-logic)
* [Validation](#jwt-validation)
  * [Detecting error types](#detecting-error-types)
* [Serialization](#jwt-serialization)
  * [Serialize using JWS](#serialize-using-jws)
  * [Serialize using JWE and JWS](#serialize-using-jwe-and-jws)
  * [Serialize the `aud` field as a string](#serialize-aud-field-as-a-string)
* [Working with JWT](#working-with-jwt)
  * [Get/Set fields](#getset-fields)

---

# Terminology

## Verification

We use the terms "verify" and "verification" to describe the process of ensuring the integrity of the JWT, namely the signature verification.

## Validation

We use the terms "validate" and "validation" to describe the process of checking the contents of a JWT, for example if the values in fields such as "iss", "sub", "aud" match our expected values, and/or if the token has expired.

# Parsing

## Parse a JWT

To parse a JWT in either raw JSON or JWS compact serialization format, use [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Parse)

<!-- INCLUDE(examples/jwt_parse_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_Parse() {
  // Note: this JWT has NOT been verified because we have not
  // passed jwt.WithKey() et al. You need to pass these values
  // if you want the token to be parsed and verified in one go
  tok, err := jwt.Parse([]byte(exampleJWTSignedHMAC))
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
  "io/ioutil"
  "log"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ReadFile() {
  f, err := ioutil.TempFile(``, `snippet_jwt_readfile-*.jws`)
  if err != nil {
    log.Printf(`failed to create temporary file: %s`, err)
    return
  }
  defer os.Remove(f.Name())

  fmt.Fprintf(f, exampleJWTSignedHMAC)
  f.Close()

  // Note: this JWT has NOT been verified because we have not
  // passed jwt.WithKey() et al. You need to pass these values
  // if you want the token to be parsed and verified in one go
  tok, err := jwt.ReadFile(f.Name())
  if err != nil {
    log.Printf(`failed to read file %q: %s`, f.Name(), err)
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
    // Note: this JWT has NOT been verified because we have not
    // passed jwt.WithKey() et al. You need to pass these values
    // if you want the token to be parsed and verified in one go
    tok, err := jwt.ParseRequest(req, tc.options...)
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

To parse a JWT *and* verify that its content matches the signature as described in the JWS message, you need to add some options when calling the [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Parse) function. Let's assume the signature was generated using ES256:

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

  tok, err := jwt.Parse([]byte(exampleJWTSignedHMAC), jwt.WithKey(jwa.HS256, key))
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

To parse a JWT *and* verify that its content matches the signature as described in the JWS message using a [`jwk.Set`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Set), you need to add some options when calling the [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Parse) function. Let's assume the JWS contains the "kid" header of the key that generated the signature:

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
    realKey, err := jwk.New(privKey)
    if err != nil {
      fmt.Printf("failed to create JWK: %s\n", err)
      return
    }
    realKey.Set(jwk.KeyIDKey, `mykey`)
    realKey.Set(jwk.AlgorithmKey, jwa.RS256)

    // For demonstration purposes, we also create a bogus key
    bogusKey := jwk.NewSymmetricKey()
    bogusKey.Set(jwk.AlgorithmKey, jwa.NoSignature)
    bogusKey.Set(jwk.KeyIDKey, "otherkey")

    // Now create a key set that users will use to verity the signed serialized against
    // Normally these keys are available somewhere like https://www.googleapis.com/oauth2/v3/certs
    // This key set contains two keys, the first one is the correct one

    // We can use the jwk.PublicSetOf() utility to get a JWKS
    // all of the public keys
    {
      privset := jwk.NewSet()
      privset.Add(realKey)
      privset.Add(bogusKey)
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

Or, if you want to switch which `jwk.Set` to use depending on the contents of the unverified token, you can use the `jwt.WithKeySetProvider` option.

```go
provider := jwt.KeySetProviderFunc(func(tok jwt.Token) (jwk.Set, error) {
  // choose which set you want to use by inspecting tok.
  // Remeber that tok is UNVERIFIED at this point
  ...
  return keyset, nil
})

token, _ := jwt.Parse(src, jwt.WithKeySetProvider(provider))
```

While the above examples will correctly verify the message if the keys in jwk.Set have the "alg" field populated with a proper value, it will promptly return an error if the "alg" field is invalid (e.g. empty).

This is because we default on the side of safety and require the "alg" field of the key to contain the actual algorithm.The general stance that we take when verifying JWTs is that we don't really trust what the values on the JWT (or actually, the JWS message) says, so we don't just use their `alg` value. This is why we require that users specify the `alg` field in the `jwt.WithVerify` option for single keys.

When you using JWKS, one way to overcome this is to explicitly populate the value of "alg" field by hand prior to using the key.

However, we realize this is cumbersome, and sometimes you just don't know what the algorithm used was.

In such cases you can use the `jwt.InferAlgorithmFromKey()` option:

```go
token, _ := jwt.Parse(src, jwt.WithKeySet(keyset, jws.InferAlgorithmFromKey(true)))
```

This will tell `jwx` to use heuristics to deduce the algorithm used. It's a brute-force approach, and does not always provide the best performance, but it will try all possible algorithms available for a given key type until one of them matches. For example, for an RSA key (either raw key or `jwk.Key`) algorithms such as RS256, RS384, RS512, PS256, PS384, and PS512 are tried.

In most cases use of this option would Just Work. However, this type of "try until something works" is not really recommended from a security perspective, and that is why the option is not enabled by default.

## Parse and Verify a JWT (using key specified in "jku")

You can parse JWTs using the JWK Set specified in the`jku` field in the JWS message by telling `jwt.Parse()` to
use `jws.VerifyAuto()` instead of `jws.Verify()`:

```go
token, _ := jwt.Parse(
  src,
  jwt.WithVerifyAuto(nil, jwt.WithFetchWhitelist(...)),
)
```

This feature must be used with extreme caution. Please see the caveats and fine prints
in the documentation for `jws.VerifyAuto()`

## Parse and Verify a JWT (using custom key retrieval logic)

Consider a case where you want to load the key to verify a Token from a database.
In this case you can use `jws.KeyProvider`:

```go
token, _ := jwt.Parse(
  src,
  jwt.WithKeyProvider(jwt.WithKeyProviderFunc(func(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
    // Use current signature or the message as hint to
    // look for the key, perhaps KeyID()
    kid := sig.ProtectedHeaders().KeyID()
    alg, key, err := loadKey(kid)
    if err != nil {
      return err
    }

    sink.Key(alg, key)
    return nil
  })),
)
```

# JWT Validation

To validate if the JWT's contents, such as if the JWT contains the proper "iss","sub","aut", etc, or the expiration information and such, use the [`jwt.Validate()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Validate) function.

```go
if err := jwt.Validate(token); err != nil {
	return errors.New(`failed to validate token`)
}
```

By default we only check for the time-related components of a token, such as "iat", "exp", and "nbf". To tell [`jwt.Validate()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#Validate) to check for other fields, use one of the various [`jwt.ValidateOption`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwt#ValidateOption) values.

```go
// Check for token["iss"] == "github.com/lestrrat-go/jwx/v2"
if err := jwt.Validate(token, jwt.WithIssuer(`github.com/lestrrat-go/jwx/v2`)) {
  return errors.New(`failed to validate token`)
}
```

You may also create a custom validator that implements the `jwt.Validator` interface. These validators can be added as an option to `jwt.Validate()` using `jwt.WithValidator()`. Multiple validators can be specified. The error should be of type `jwt.ValidationError`. Use `jwt.NewValidationError` to create an error of appropriate type.

```go
validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) error {
  if time.Now().Month() != 8 {
    return jwt.NewValidationError(errors.New(`tokens are only valid during August!`))
  }
  return nil
})
if err := jwt.Validate(token, jwt.WithValidator(validator)); err != nil {
  ...
}
```

## Detecting error types

If you enable validation during `jwt.Parse()`, you might sometimes want to differentiate between parsing errors and validation errors. To do this, you can use the function `jwt.IsValidationError()`. To further differentiate between specific errors, you can use `errors.Is()`:

```go
token, err := jwt.Parse(src, jwt.WithValidat(true))
if err != nil {
  if jwt.IsValidationError(err) {
    switch {
    case errors.Is(err, jwt.ErrTokenExpired()):
      ...
    case errors.Is(err, jwt.ErrTokenNotYetValid()):
      ...
    case errors.Is(err, jwt.ErrInvalidIssuedAt()):
      ...
    default:
      ...
    }
  }
}
```

# JWT Serialization

## Serialize using JWS

The `jwt` package provides a convenience function `jwt.Sign()` to serialize a token using JWS.

```go
token := jwt.New()
token.Set(jwt.IssuerKey, `github.com/lestrrat-go/jwx/v2`)

serialized, err := jwt.Sign(token, jwt.WithKey(algorithm, key))
```

If you need even further customization, consider using the `jws` package directly.

## Serialize using JWE and JWS

The `jwt` package provides a `Serializer` object to allow users to serialize a token using an arbitrary combination of processors. For example, to encrypt a token using JWE, then use JWS to sign it, do the following:

```go
serizlied, err := jwt.NewSerializer().
  Encrypt(keyEncryptionAlgorithm, keyEncryptionKey, contentEncryptionAlgorithm, compression).
  Sign(signatureAlgorithm, signatureKey).
  Serialize(token)
```

If for whatever reason the buil-tin `(jwt.Serializer).Sign()` and `(jwt.Serializer).Encrypt()` do not work for you, you may choose to provider a custom serialization step using `(jwt.Serialize).Step()`

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

To workaround these problematic parsers, you may use the `jwt.Settings()` function with the `jwt.WithFlattenAudience(true)` option.

```go
func init() {
  jwt.Settings(jwt.WithFlattenAudience(true))
}
```

The above call will force all calls to marshal JWT tokens to flatten the `aud` field when it can. This has global effect.

# Working with JWT

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
