# Working with JWS

In this document we describe how to work with JWS using `github.com/lestrrat-go/jwx/jws`

# Parsing

## Getting the payload from a JWS encoded buffer

If you want to get the payload in the JWS message after it has been verified, use `jws.Verify()`

```go
var encoded = []byte{...}
payload, _ := jws.Verify(encoded, alg, key)
```

You must provide the algorithm and the public key to use for verification.
Please read "[Why don't you automatically infer the algorithm for jws.Verify?](https://github.com/lestrrat-go/jwx#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)" for why this is necessary.

If the algorithm or the key does not match, an error is returned.

## Parse a JWS encoded buffer into a jws.Message

You can parse a JWS buffer into a `jws.Message` object. In this mode, there is no verification performed.

```go
var payload = []byte{...}
msg, _ := jws.Parse(payload)
```

Note that `jws.Message` is not really built for general signing/verification usage.
It's built more so for inspection purposes.
Think twice before attempting to do anything more than inspection using `jws.Message`.

# Signing

## Generating a JWS message in compact serialization format

In most cases this is all you really need.

```go
encoded, _ := jws.Sign(payload, alg, key)
```

To sign a JWT, use `jwt.Sign()`

```go
encoded, _ := jwt.Sign(token, alg, key)
```

## Generating a JWS message in JSON serialization format

Generally the only time you need to use a JSON serialization format is when you have to generate multiple signatures for a given payload using multiple signing algorithms and keys.
When this need arises, use the `jws.SignMulti()` method.

```go
signer, _ := jws.NewSigner(alg)
encoded, _ := jws.SignMulti(payload, jws.WithSigner(signer, key, pubHeaders, protHeaders)
```

# Using a custom signing/verification algorithm

Sometimes we do not offer a particular algorithm out of the box, but you have an implementation for it.

In such scenarios, you can use the `jws.RegisterSigner()` and `jws.RegisterVerifier()` functions to
generate your own verifier instance. 

```go
jws.RegisterSigner(alg, signerFactory)
jws.RegisterVerifier(alg, verifierFactory)
```
