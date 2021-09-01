# Working with JWS

In this document we describe how to work with JWS using [`github.com/lestrrat-go/jwx/jws`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws)

* [Parsing](#parsing)
  * [Getting the payload from a JWS encoded buffer](#getting-the-payload-from-a-jws-encoded-buffer)
  * [Parse a JWS encoded buffer into a jws.Message](#parse-a-jws-encoded-buffer-into-a-jwsmessage)
  * [Parse a JWS encoded message stored in a file](#parse-a-jws-encoded-message-stored-in-a-file)
* [Signing](#signing)
  * [Generating a JWS message in compact serialization format](#generating-a-jws-message-in-compact-serialization-format)
  * [Generating a JWS message in JSON serialization format](#generating-a-jws-message-in-json-serialization-format)
* [Using a custom signing/verification algorithm](#using-a-customg-signingverification-algorithm)
* [Enabling ES256K](#enabling-es256k)
# Parsing

## Getting the payload from a JWS encoded buffer

If you want to get the payload in the JWS message after it has been verified, use [`jws.Verify()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#Verify)

```go
var encoded = []byte{...}
payload, _ := jws.Verify(encoded, alg, key)
```

You must provide the algorithm and the public key to use for verification.
Please read "[Why don't you automatically infer the algorithm for jws.Verify?](https://github.com/lestrrat-go/jwx#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)" for why this is necessary.

If the algorithm or the key does not match, an error is returned.

## Parse a JWS encoded buffer into a jws.Message

You can parse a JWS buffer into a [`jws.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#Message) object. In this mode, there is no verification performed.

```go
var payload = []byte{...}
msg, _ := jws.Parse(payload)
```

Note that [`jws.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#Message) is not really built for general signing/verification usage.
It's built more so for inspection purposes.
Think twice before attempting to do anything more than inspection using [`jws.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#Message).

## Parse a JWS encoded message stored in a file

To parsea JWS stored in a file, use [`jws.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#ReadFile). [`jws.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#ReadFile) accepts the same options as [`jws.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#Parse).

```go
message, _ := jwt.ReadFile(`message.jws`)
```

# Signing

## Generating a JWS message in compact serialization format

In most cases this is all you really need.

```go
encoded, _ := jws.Sign(payload, alg, key)
```

To sign a JWT, use [`jwt.Sign()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#Sign)

```go
encoded, _ := jwt.Sign(token, alg, key)
```

## Generating a JWS message in JSON serialization format

Generally the only time you need to use a JSON serialization format is when you have to generate multiple signatures for a given payload using multiple signing algorithms and keys.
When this need arises, use the [`jws.SignMulti()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#SignMulti) method.

```go
signer, _ := jws.NewSigner(alg)
encoded, _ := jws.SignMulti(payload, jws.WithSigner(signer, key, pubHeaders, protHeaders)
```

# Using a custom signing/verification algorithm

Sometimes we do not offer a particular algorithm out of the box, but you have an implementation for it.

In such scenarios, you can use the [`jws.RegisterSigner()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#RegisterSigner) and [`jws.RegisterVerifier()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#RegisterVerifier) functions to
generate your own verifier instance. 

```go
jws.RegisterSigner(alg, signerFactory)
jws.RegisterVerifier(alg, verifierFactory)
```

# Enabling ES256K

See [Enabling Optional Signature Methods](./20-global-settings.md#enabling-optional-signature-methods)
