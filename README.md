# github.com/lestrrat-go/jwx ![](https://github.com/lestrrat-go/jwx/workflows/CI/badge.svg) [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx) [![codecov.io](http://codecov.io/github/lestrrat-go/jwx/coverage.svg?branch=master)](http://codecov.io/github/lestrrat-go/jwx?branch=master)

Command line tool [jwx](./cmd/jwx) and libraries implementing various JWx technologies

| Package name                                              | Notes                                           |
|-----------------------------------------------------------|-------------------------------------------------|
| [jwt](https://github.com/lestrrat-go/jwx/tree/master/jwt) | [RFC 7519](https://tools.ietf.org/html/rfc7519) |
| [jwk](https://github.com/lestrrat-go/jwx/tree/master/jwk) | [RFC 7517](https://tools.ietf.org/html/rfc7517) + [RFC 7638](https://tools.ietf.org/html/rfc7638) |
| [jwa](https://github.com/lestrrat-go/jwx/tree/master/jwa) | [RFC 7518](https://tools.ietf.org/html/rfc7518) |
| [jws](https://github.com/lestrrat-go/jwx/tree/master/jws) | [RFC 7515](https://tools.ietf.org/html/rfc7515) |
| [jwe](https://github.com/lestrrat-go/jwx/tree/master/jwe) | [RFC 7516](https://tools.ietf.org/html/rfc7516) |

## Why?

My goal was to write a server that heavily uses JWK and JWT. At first glance
the libraries that already exist seemed sufficient, but soon I realized that

1. To completely implement the protocols, I needed the entire JWT, JWK, JWS, JWE (and JWA, by necessity).
2. Most of the libraries that existed only deal with a subset of the various JWx specifications that were necessary to implement their specific needs

For example, a certain library looks like it had most of JWS, JWE, JWK covered, but then it lacked the ability to include private claims in its JWT responses. Another library had support of all the private claims, but completely lacked in its flexibility to generate various different response formats.

Because I was writing the server side (and the client side for testing), I needed the *entire* JOSE toolset to properly implement my server, **and** they needed to be *flexible* enough to fulfill the entire spec that I was writing.

So here's `github.com/lestrrat-go/jwx`. This library is extensible, customizable, and hopefully well organized to the point that it is easy for you to slice and dice it.

## Backwards Compatibility Notice

### Users of github.com/lestrrat/go-jwx

Uh, why are you using such an ancient version? You know that repository is archived for a reason, yeah? Please use the new version.

### Pre-1.0.0 users

The API has been reworked quite substantially between pre- and post 1.0.0 releases. Please check out the [Changes](./Changes) file (or the [diff](https://github.com/lestrrat-go/jwx/compare/v0.9.2...v1.0.0), if you are into that sort of thing)

### v1.0.x users

The API has gone under some changes for v1.1.0. If you are upgrading, you might want to read the relevant parts in the [Changes](./Changes) file.

# Command Line Tool

Since v1.1.1 we have a command line tool `jwx` (*). With `jwx` you can create JWKs (from PEM files, even), sign and verify JWS message, encrypt and decrypt JWE messages, etc.

(*) Okay, it existed since a long time ago, but it was never useful.

## Installation

```
go install github.com/lestrrat-go/jwx/cmd/jwx
```

# Packages

## JWA [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/jwa.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwa)

Package [github.com/lestrrat-go/jwx/jwa](./jwa) defines the various algorithm described in [RFC7518](https://tools.ietf.org/html/rfc7518)

## JWT [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/jwt.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt)

Package [github.com/lestrrat-go/jwx/jwt](./jwt) implements JSON Web Tokens as described in [RFC7519](https://tools.ietf.org/html/rfc7519).

* Convenience methods for oft-used keys ("aud", "sub", "iss", etc)
* Ability to Get/Set arbitrary keys
* Conversion to and from JSON
* Generate signed tokens
* Verify signed tokens
* Extra support for OpenID tokens via [github.com/lestrrat-go/jwx/jwt/openid](./jwt/openid)

Examples are located in the examples directory ([jwt_example_test.go](./examples/jwt_example_test.go))

## JWK [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/jwk.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk)

Package [github.com/lestrrat-go/jwx/jwk](./jwk) implements JWK as described in [RFC7517](https://tools.ietf.org/html/rfc7517)

* Parse and work with RSA/EC/Symmetric/OKP JWK types
  * Convert to and from JSON
  * Convert to and from raw key types (e.g. *rsa.PrivateKey)
* Ability to keep a JWKS fresh.
* Add arbitrary fields in the JWK object

Examples are located in the examples directory ([jwk_example_test.go](./examples/jwk_example_test.go))

Supported key types:

| kty | Curve                   | Go Key Type                                   |
|:----|:------------------------|:----------------------------------------------|
| RSA | N/A                     | rsa.PrivateKey / rsa.PublicKey (2)            |
| EC  | P-256<br>P-384<br>P-521 | ecdsa.PrivateKey / ecdsa.PublicKey (2)        |
| oct | N/A                     | []byte                                        |
| OKP | Ed25519 (1)             | ed25519.PrivateKey / ed25519.PublicKey (2)    |
|     | X25519 (1)              | (jwx/)x25519.PrivateKey / x25519.PublicKey (2)|

* Note 1: Experimental
* Note 2: Either value or pointers accepted (e.g. rsa.PrivateKey or *rsa.PrivateKey)

## JWS [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/jws.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/jws)

Package [github.com/lestrrat-go/jwx/jws](./jws) implements JWS as described in [RFC7515](https://tools.ietf.org/html/rfc7515)

* Parse and generate compact or JSON serializations
* Sign and verify arbitrary payload
* Use any of the keys supported in [github.com/lestrrat-go/jwx/jwk](./jwk)
* Add arbitrary fields in the JWS object
* Ability to add/replace existing signature methods

Examples are located in the examples directory ([jws_example_test.go](./examples/jws_example_test.go))

Supported signature algorithms:

| Algorithm                               | Supported? | Constant in [jwa](./jwa) |
|:----------------------------------------|:-----------|:-------------------------|
| HMAC using SHA-256                      | YES        | jwa.HS256                |
| HMAC using SHA-384                      | YES        | jwa.HS384                |
| HMAC using SHA-512                      | YES        | jwa.HS512                |
| RSASSA-PKCS-v1.5 using SHA-256          | YES        | jwa.RS256                |
| RSASSA-PKCS-v1.5 using SHA-384          | YES        | jwa.RS384                |
| RSASSA-PKCS-v1.5 using SHA-512          | YES        | jwa.RS512                |
| ECDSA using P-256 and SHA-256           | YES        | jwa.ES256                |
| ECDSA using P-384 and SHA-384           | YES        | jwa.ES384                |
| ECDSA using P-521 and SHA-512           | YES        | jwa.ES512                |
| RSASSA-PSS using SHA256 and MGF1-SHA256 | YES        | jwa.PS256                |
| RSASSA-PSS using SHA384 and MGF1-SHA384 | YES        | jwa.PS384                |
| RSASSA-PSS using SHA512 and MGF1-SHA512 | YES        | jwa.PS512                |
| EdDSA (1)                               | YES        | jwa.EdDSA                |

* Note 1: Experimental

## JWE [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/jwe.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwe)

Package [github.com/lestrrast-go/jwx/jwe](./jwe) implements JWE as described in [RFC7516](https://tools.ietf.org/html/rfc7516)

* Encrypt and Decrypt arbitrary data
* Content compression and decompression
* Add arbitrary fields in the JWE header object

Examples are located in the examples directory ([jwe_example_test.go](./examples/jwe_example_test.go))

Supported key encryption algorithm:

| Algorithm                                | Supported? | Constant in [jwa](./jwa) |
|:-----------------------------------------|:-----------|:-------------------------|
| RSA-PKCS1v1.5                            | YES        | jwa.RSA1_5               |
| RSA-OAEP-SHA1                            | YES        | jwa.RSA_OAEP             |
| RSA-OAEP-SHA256                          | YES        | jwa.RSA_OAEP_256         |
| AES key wrap (128)                       | YES        | jwa.A128KW               |
| AES key wrap (192)                       | YES        | jwa.A192KW               |
| AES key wrap (256)                       | YES        | jwa.A256KW               |
| Direct encryption                        | YES (1)    | jwa.DIRECT               |
| ECDH-ES                                  | YES (1)    | jwa.ECDH_ES              |
| ECDH-ES + AES key wrap (128)             | YES        | jwa.ECDH_ES_A128KW       |
| ECDH-ES + AES key wrap (192)             | YES        | jwa.ECDH_ES_A192KW       |
| ECDH-ES + AES key wrap (256)             | YES        | jwa.ECDH_ES_A256KW       |
| AES-GCM key wrap (128)                   | YES        | jwa.A128GCMKW            |
| AES-GCM key wrap (192)                   | YES        | jwa.A192GCMKW            |
| AES-GCM key wrap (256)                   | YES        | jwa.A256GCMKW            |
| PBES2 + HMAC-SHA256 + AES key wrap (128) | YES        | jwa.PBES2_HS256_A128KW   |
| PBES2 + HMAC-SHA384 + AES key wrap (192) | YES        | jwa.PBES2_HS384_A192KW   |
| PBES2 + HMAC-SHA512 + AES key wrap (256) | YES        | jwa.PBES2_HS512_A256KW   |

* Note 1: Single-recipient only

Supported content encryption algorithm:

| Algorithm                   | Supported? | Constant in [jwa](./jwa) |
|:----------------------------|:-----------|:-------------------------|
| AES-CBC + HMAC-SHA256 (128) | YES        | jwa.A128CBC_HS256        |
| AES-CBC + HMAC-SHA384 (192) | YES        | jwa.A192CBC_HS384        |
| AES-CBC + HMAC-SHA512 (256) | YES        | jwa.A256CBC_HS512        |
| AES-GCM (128)               | YES        | jwa.A128GCM              |
| AES-GCM (192)               | YES        | jwa.A192GCM              |
| AES-GCM (256)               | YES        | jwa.A256GCM              |

# Global Settings

## Switching to a faster JSON library

By default we use the standard library's `encoding/json` for all of our JSON needs.
However, if performance for parsing/serializing JSON is really important to you, you might want to enable [github.com/goccy/go-json](https://github.com/goccy/go-sjon) by enabling the `jwx_goccy` tag.

```shell
% go build -tags jwx_goccy ...
```

[github.com/goccy/go-json](https://github.com/goccy/go-sjon) is *disabled* by default because it uses some really advanced black magic, and I really do not feel like debugging it **IF** it breaks. Please note that that's a big "if".
As of github.com/goccy/go-json@v0.3.3 I haven't see any problems, and I would say that it is mostly stable.

However, it is a depdenency that you can go without, and I won't be of much help if it breaks -- therefore it is not the default.
If you know what you are doing, I highly recommend enabling this module -- all you need to do is to enable this tag.
Disable the tag if you feel like it's not worth the hassle.

And when you *do* enable [github.com/goccy/go-json](https://github.com/goccy/go-sjon) and you encounter some mysterious error, I also trust that you know to file an issue to [github.com/goccy/go-json](https://github.com/goccy/go-sjon) and **NOT** to this library.

## Using json.Number

If you want to parse numbers in the incoming JSON objects as json.Number
instead of floats, you can use the following call to globally affect the behavior of JSON parsing.

```go
func init()
  jwx.DecoderSettings(jwx.WithUseNumber(true))
}
```

Do be aware that this has *global* effect. All code that calls in to `encoding/json`
within `jwx` *will* use your settings.

# Other related libraries:

* https://github.com/dgrijalva/jwt-go
* https://github.com/square/go-jose
* https://github.com/coreos/oidc
* https://golang.org/x/oauth2

# Contributions

## Issues

For bug reports and feature requests, please try to follow the issue templates as much as possible.
For either bug reports or feature requests, failing tests are even better.

## Pull Requests

Please make sure to include tests that excercise the changes you made.

## Discussions / Usage

Please try [discussions](./discussions) first.

# Credits

* Work on this library was generously sponsored by HDE Inc (https://www.hde.co.jp)
* Lots of code, especially JWE was taken from go-jose library (https://github.com/square/go-jose)
* Lots of individual contributors have helped this project over the years. Thank each and everyone of you very much.

# FAQ

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
If you are in an environment where API changes disrupts your environment, you should definitely migrade to using Go modules now.
