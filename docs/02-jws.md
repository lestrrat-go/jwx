# Working with JWS

In this document we describe how to work with JWS using [`github.com/lestrrat-go/jwx/jws`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws)

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

If you want to get the payload in the JWS message after it has been verified, use [`jws.Verify()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#Verify)

```go
var encoded = []byte{...}
payload, _ := jws.Verify(encoded, alg, key)
```

You must provide the algorithm and the public key to use for verification.
Please read "[Why don't you automatically infer the algorithm for `jws.Verify`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)"

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

To parse a JWS stored in a file, use [`jws.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#ReadFile). [`jws.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#ReadFile) accepts the same options as [`jws.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#Parse).

```go
message, _ := jws.ReadFile(`message.jws`)
```

## Verify a JWS with detached payload

To parse a JWS with detached payload, use the `jws.WithDetachedPayload()` option:

```go
signed, _ := jws.Verify(signed, alg, key, jws.WithDetachedPayload(payload))
```

# Signing

## Generating a JWS message in compact serialization format

In most cases this is all you really need.

```go
signed, _ := jws.Sign(payload, alg, key)
```

To sign a JWT, use [`jwt.Sign()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#Sign)

```go
signed, _ := jwt.Sign(token, alg, key)
```

## Generating a JWS message in JSON serialization format

Generally the only time you need to use a JSON serialization format is when you have to generate multiple signatures for a given payload using multiple signing algorithms and keys.
When this need arises, use the [`jws.SignMulti()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#SignMulti) method.

```go
signer, _ := jws.NewSigner(alg)
signed, _ := jws.SignMulti(payload, jws.WithSigner(signer, key, pubHeaders, protHeaders)
```

## Generating a JWS message with detached payload

Use the `jws.WithDetachedPayload()` option to sign a detached payload:

```go
signed, _ := jws.Sign(nil, alg, key, jws.WithDetachedPayload(payload))
```

## Including Arbitrary Headers to Compact Serialization

By default, only some header fields are included in the result from `jws.Sign()`.
If you want to include more headers fields in the resulting JWS, you will have to provide them via the `jws.WithHeaders()` option

```go
hdrs := jws.NewHeaders()
hdrs.Set(`arbitrary-key`, `value`)
signed, _ := jws.Sign(payload, alg, key, jws.WithHEaders(hdrs))
```

## Using cloud KMS services

If you want to use cloud KMSes such as AWS KMS to sign and verify payloads, look for an object that implements
`crypto.Signer`. There are some [implementations written for this module](https://github.com/jwx-go/crypto-signer).

Event if you cannot find an implementation that you are looking for in the above repository, any other implementation that implements `crypto.Signer` should work.

# Verifying

## Verification using a single key

Simply use `jws.Verify()`. It will automatically do the right thing whether it's serialized in compact
form or JSON form.

```go
payload, _ := jws.Verify(data, alg, key)
```

The `alg` must be explicitly specified. See "[Why don't you automatically infer the algorithm for `jws.Verify`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)"

To verify a JWS message with detached payload, use the `jws.WithDetachedPayload()` option:

```go
_, err := jws.Verify(data, alg, key, jws.WithDetachedPayload(payload))
```

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

In such scenarios, you can use the [`jws.RegisterSigner()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#RegisterSigner) and [`jws.RegisterVerifier()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws#RegisterVerifier) functions to
generate your own verifier instance. 

```go
jws.RegisterSigner(alg, signerFactory)
jws.RegisterVerifier(alg, verifierFactory)
```

# Enabling ES256K

See [Enabling Optional Signature Methods](./20-global-settings.md#enabling-optional-signature-methods)
