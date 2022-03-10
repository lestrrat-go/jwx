# Frequently asked questions

## I want to use this with a Web Framework

### Echo

Consider using [github.com/lestrrat-go/echo-middleware-jwx](github.com/lestrrat-go/echo-middleware-jwx), although as of this writing it has not been widely tested.

## I get a "no Go files in ..." error

You are using Go in GOPATH mode. Short answer: use Go modules.

[A slightly more elaborate version of the answer can be found in github.com/lestrrat-go/backoff FAQ](https://github.com/lestrrat-go/backoff#im-getting-package-githubcomlestrrat-gobackoffv2-no-go-files-in-gosrcgithubcomlestrrat-gobackoffv2)

And no, I do not intend to support GOPATH mode as of 2021. There are ways to manually workaround it, but do not expect this library to do that for you.

## Why don't you automatically infer the algorithm for `jws.Verify` ?

Please read https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/. Despite this article's publish date, the original had been published sometime around 2015. It's a well known problem with JWS libraries.

## Why did you change the API?

Presumably you are asking this because your code broke when we bumped the version and broke backwards compatibility. Then the short answer is: "You wouldn't have had to worry about it if you were properly using go.mod"

The longer answer is as follows: From time to time, we introduce API changes, because we learn of mistakes in our old ways.
Maybe we used the wrong terminology. Maybe we made public something that should have been internal. Maybe we intended an API to be used one way, but it was confusing.

So then we introduce API changes. Sorry if breaks your builds, but it's done because we deem it necessary.

You should also know that we do not introduce API changes between micro versions.
And on top of that, Go provides extremely good support for idempodent builds via Go modules.
If you are in an environment where API changes disrupts your environment, you should definitely migrate to using Go modules now.


## "Why can't I create my jwk.Key?"

### 1. You are passing the wrong parameter to `jwk.New()`.

As stated in the documentation, `jwk.New()` creates different types of keys depending on the type of the input.

Use `jwk.New()` to construct a JWK from the [*raw* key](./04-jwk.md#raw-key). Use `jwk.Parse()` or `jwk.ParseKey()` to parse a piece of data (`[]byte` and the like) and create the appropriate key type from its contents.

See ["Using jwk.New()"](./04-jwk.md#using-jwknew) for more details.

### 2. You are not decoding PEM.

When you read from a PEM encoded file (e.g. `key.pem`), you cannot just parse it using `jwk.Parse()` as by default we do not expect the data to be PEM encoded. Use `jwk.WithPEM(true)` for this.

See ["Parse a key or set in PEM format"](./04-jwk.md#parse-a-key-or-a-set-in-pem-format) for more details.

## "Why is my code to call `jwt.Sign()`/`jws.Verify()` failing?"

### 1. Your algorithm and key type do not match.

Any given signature algorithm requires a particular type of key. If the pair is not setup correctly, the operation will fail. Below is a table of general algorithm to key type pair. Note that this table may not be updated regularly. Use common sense and search online to find out if the algorithm/key type you would like to use is not listed in the table.

| Algorithm Family | Key Type  |
|------------------|-----------|
| jwa.HS\*\*\*     | Symmetric |
| jwa.RS\*\*\*     | RSA       |
| jwa.ES\*\*\*     | Elliptic  |

### 2. You are mixing up when to use private/public keys.

You sign using a private key. You verify using a public key (although, it is possible to verify using the private key, but is not really a common operation).

So, for example, a service like Google will sign their JWTs using their private keys which are not publicly available, but will provide the public keys somewhere so that you can verify their JWTs using those public keys.

### 3. You are parsing the wrong token.

Often times we have people asking us about github.com/lestrrat-go/jwx/v2/jwt not being able to parse a token... except, they are not JWTs.

For example, when a provider says they will give you an "access token" ... well, it *may* be a JWT, but often times they are just some sort of string key (which will definitely parse if you pass it to `jwt.Parse`). Sometimes what you really want is stored in a different token, and it may be called an "ID token". Who knows, these things vary between implementation to implemention.

After all, the only thing we can say is that you should check that you are parsing. 

## Why are you generating so many fields?

Because a lot of the code is repetitive. For example, maintaining the 15 fields in a JWE header in all parts of the code (getter methods, setter methods, marshaling/unmarshaling) is doable but very very very cumbersome. We think that resources used for watching out for typos and other minor problems that may arise during maintenance is better spent elsewhere by automating generation of consistent code.

## Why is (jwk.Key).Algorithm() and jwa.KeyAlgorithm so confusing?

To start, we sympathize. Please read on for the reason(s) why things are the way they are.

First you must understand that JWKs can be used for multiple different purposes, including but not limited to JWS and JWE (key encryption). And the `alg` field is supposed to carry to what purpose the JWK is supposed to be used.

This means that a JWK can, in jwx terms, carry either `jwa.SignatureAlgorithm` or `jwa.KeyEncryptionAlgorithm`.

In order to allow passing either `jwa.SignatureAlgorithm` or `jwa.KeyEncrypionAlgorithm`, we initially implemented
`(jwk.Key).Algorithm()` as a string, so it was possible to just change the type depending on the situation.

This caused a bit of confusion for some users because this field was the only "untyped" field that potentially could have been typed. Most notably, some people wanted to do the following, but couldn't:

```go
jwt.Verify(token, jwt.WithKey(key.Algorithm(), key))
```

Since version 2.0.0 `jwk.Key` now stores the `alg` field as a `jwa.KeyAlgorithm` type, which is just an interface that covers `jwa.SignatureAlgorithm`, `jwa.KeyEncryptionAlgorithm`, or any other type that we may need to represent in the future.

Now you should be able to just pass the `alg` value to most high-level functions and methods such as `jwt.Verify`, `jws.Sign`, and `jwe.Encrypt`

### When do we use `jwa.KeyAlgorithm`

There are some functions that accept `jwa.KeyAlgorithm`, while there are others that expect `jwa.SignatureAlgorithm` or `jwa.KeyEncryptionAlgorithm`. So when do we use which?

The guideline is as follows: If it's a high-level function/method that the users regularly use, use `jwa.KeyAlgorithm`. For example, almost everybody who use `jwt` will want to verify the JWS signed payload, so `jwt.Sign()`, and `jwt.Verify()` expect `jwa.KeyAlgorithm`. On the other hand, `jwt.Serializer` uses `jwa.SignatureAlgorithm` and such. This is a low-level utility, and users are not really meant to use it for their most basic needs: therefore they use the specific algorithm type.
