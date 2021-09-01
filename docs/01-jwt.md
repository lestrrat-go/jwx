# Working with JWT

In this document we describe how to work with JWT using `github.com/lestrrat-go/jwx/jwt`

* [Terminology](#terminology)
  * [Verification](#verification)
  * [Validation](#validation)
* [Parsing](#parsing)
  * [Parse a JWT](#parse-a-jwt)
  * [Parse a JWT from file](#parse-a-jwt-from-file)
  * [Parse a JWT from a *http.Request](#parse-a-jwt-from-a-httprequest)
* [Verification](#jwt-verification)
  * [Parse and Verify a JWT (with a single key)](#parse-and-verify-a-jwt-with-single-key)
  * [Parse and Verify a JWT (with a key set, matching "kid")](#parse-and-verify-a-jwt-with-a-key-set-matching-kid)
* [Validation](#jwt-validation)
* [Serialization](#jwt-serialization)
  * [Serialize using JWS](#serialize-using-jws
  * [Serialize using JWE and JWS](#serialize-using-jwe-and-jws)
  * [Serialize the `aud` field as a string](#serialize-aud-field-as-a-string)

---

# Terminology

## Verification

We use the terms "verify" and "verification" to describe the process of ensuring the integrity of the JWT, namely the signature verification.

## Validation

We use the terms "validate" and "validation" to describe the process of checking the contents of a JWT, for example if the values in fields such as "iss", "sub", "aud" match our expected values, and/or if the token has expired.

# Parsing

## Parse a JWT

To parse a JWT in either raw JSON or JWS compact serialization format, use [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#Parse)

```go
src := []byte{...}
token, _ := jwt.Parse(src)
```

Note that the above form does NOT perform any signature verification, or validation of the JWT token itself.
This just reads the contents of src, and maps it into the token, period.
In order to perform verification/validation, please see the methods described elsewhere in this document, and pass the appropriate option(s).

## Parse a JWT from file

To parsea JWT stored in a file, use [`jwt.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#ReadFile). [`jwt.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#ReadFile) accepts the same options as [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#Parse).

```go
token, _ := jwt.ReadFile(`token.json`)
```

## Parse a JWT from a *http.Request

To parse a JWT stored within a *http.Request object, use [`jwt.ParseRequest()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#ParseRequest). It by default looks for JWTs stored in the "Authorization" header, but can be configured to look under other headers and within the form fields.

```go
// Looks under "Authorization" header
token, err := jwt.ParseRequest(req)

// Looks under "X-JWT-Token" header
token, err := jwt.ParseRequest(req, jwt.WithHeaderKey("X-JWT-Token")

// Looks under "Authorization" and "X-JWT-Token" headers
token, err := jwt.ParseRequest(req, jwt.WithHeaderKey("Authorization"), jwt.WithFormKey("X-JWT-Token"))

// Looks under "Authorization" header and "access_token" form field
token, err := jwt.ParseRequest(req, jwt.WithFormKey("access_token"))
```
# JWT Verification

## Parse and Verify a JWT (with single key)

To parse a JWT *and* verify that its content matches the signature as described in the JWS message, you need to add some options when calling the [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#Parse) function. Let's assume the signature was generated using ES256:

```go
src := []byte{...}
token, _ := jwt.Parse(src, jwt.WithVerify(jwa.ES256, key))
```

In the above example, `key` may either be the raw key (i.e. "crypto/ecdsa".PublicKey, "crypto/ecdsa".PrivateKey) or an instance of [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Key) (i.e. [`jwk.ECDSAPrivateKey`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#ECDSAPrivateKey), [`jwk.ECDSAPublicKey`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#ECDSAPublicKey)). The key type must match the algorithm being used.

## Parse and Verify a JWT (with a key set, matching "kid")

To parse a JWT *and* verify that its content matches the signature as described in the JWS message using a [`jwk.Set`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Set), you need to add some options when calling the [`jwt.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#Parse) function. Let's assume the JWS contains the "kid" header of the key that generated the signature:

```go
src := []byte{...}
token, _ := jwt.Parse(src, jwt.WithKeySet(keyset))
```

The above example will correctly verify the message if the jwk.Set specified by the variable `keyset` contains a key that matches
the key ID in the JWS message.

# JWT Validation

To validate if the JWT's contents, such as if the JWT contains the proper "iss","sub","aut", etc, or the expiration information and such, use the [`jwt.Validate()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#Validate) function.

```go
if err := jwt.Validate(token); err != nil {
	return errors.New(`failed to validate token`)
}
```

By default we only check for the time-related components of a token, such as "iat", "exp", and "nbf". To tell [`jwt.Validate()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#Validate) to check for other fields, use one of the various [`jwt.ValidateOption`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#ValidateOption) values.

```go
// Check for token["iss"] == "github.com/lestrrat-go/jwx"
if err := jwt.Validate(token, jwt.WithIssuer(`github.com/lestrrat-go/jwx`)) {
  return errors.New(`failed to validate token`)
}
```

# JWT Serialization

## Serialize using JWS

The `jwt` package provides a convenience function `jwt.Sign()` to serialize a token using JWS.

```go
token := jwt.New()
token.Set(jwt.IssuerKey, `github.com/lestrrat-go/jwx`)

serialized, err := jws.Sign(token, algorithm, key)
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

The examples below shoud both be valid, but apparently there are systems that do not understand the former ([AWS Cognito has been reported to be one such system](https://github.com/lestrrat-go/jwx/issues/368)).

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


