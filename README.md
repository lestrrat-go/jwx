# github.com/lestrrat-go/jwx/v2 ![](https://github.com/lestrrat-go/jwx/workflows/CI/badge.svg?branch=v2) [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/v2.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2) [![codecov.io](https://codecov.io/github/lestrrat-go/jwx/coverage.svg?branch=v2)](https://codecov.io/github/lestrrat-go/jwx?branch=v2)

Go module implementing various JWx (JWA/JWE/JWK/JWS/JWT, otherwise known as JOSE) technologies.

If you are using this module in your product or your company, please add  your product and/or company name in the [Wiki](https://github.com/lestrrat-go/jwx/tree/v2/wiki/Users)! It really helps keeping up our motivation.

# Features

* Complete coverage of JWA/JWE/JWK/JWS/JWT, not just JWT+minimum tool set.
* Opinionated, but very uniform API. Everything is symmetric, and follows a standard convetion

Some more in-depth discussion on why you might want to use this library over others
can be found in the [Description section](#description)

# How-to Documentation

* [API documentation](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2)
* [How-to style documentation](./docs)
* [Runnable Examples](./examples)

## Installation

```
go install github.com/lestrrat-go/jwx/v2/cmd/jwx
```

# Description

This Go module implements JWA, JWE, JWK, JWS, and JWT. Please see the following table for the list of
available packages:

| Package name                                              | Notes                                           |
|-----------------------------------------------------------|-------------------------------------------------|
| [jwt](https://github.com/lestrrat-go/jwx/tree/v2/jwt) | [RFC 7519](https://tools.ietf.org/html/rfc7519) |
| [jwk](https://github.com/lestrrat-go/jwx/tree/v2/jwk) | [RFC 7517](https://tools.ietf.org/html/rfc7517) + [RFC 7638](https://tools.ietf.org/html/rfc7638) |
| [jwa](https://github.com/lestrrat-go/jwx/tree/v2/jwa) | [RFC 7518](https://tools.ietf.org/html/rfc7518) |
| [jws](https://github.com/lestrrat-go/jwx/tree/v2/jws) | [RFC 7515](https://tools.ietf.org/html/rfc7515) + [RFC 7797](https://tools.ietf.org/html/rfc7797) |
| [jwe](https://github.com/lestrrat-go/jwx/tree/v2/jwe) | [RFC 7516](https://tools.ietf.org/html/rfc7516) |
## History

My goal was to write a server that heavily uses JWK and JWT. At first glance
the libraries that already exist seemed sufficient, but soon I realized that

1. To completely implement the protocols, I needed the entire JWT, JWK, JWS, JWE (and JWA, by necessity).
2. Most of the libraries that existed only deal with a subset of the various JWx specifications that were necessary to implement their specific needs

For example, a certain library looks like it had most of JWS, JWE, JWK covered, but then it lacked the ability to include private claims in its JWT responses. Another library had support of all the private claims, but completely lacked in its flexibility to generate various different response formats.

Because I was writing the server side (and the client side for testing), I needed the *entire* JOSE toolset to properly implement my server, **and** they needed to be *flexible* enough to fulfill the entire spec that I was writing.

So here's `github.com/lestrrat-go/jwx/v2`. This library is extensible, customizable, and hopefully well organized to the point that it is easy for you to slice and dice it.

## Why would I use this library?

There are several other major Go modules that handle JWT and related data formats,
so why should you use this library?

From a purely functional perspective, the only major difference is this:
Whereas most other projects only deal with what they seem necessary to handle
JWTs, this module handles the **_entire_** spectrum of JWS, JWE, JWK, and JWT.

That is, if you need to not only parse JWTs, but also to control JWKs, or
if you need to handle payloads that are NOT JWTs, you should probably consider
using this module. You should also note that JWT is built _on top_ of those
other technologies. You simply cannot have a complete JWT package without
implementing the entirety of JWS/JWS/JWK, which this library does.

Next, from an implementation perspective, this module differs significantly
from others in that it tries very hard to expose only the APIs, and not the
internal data. For example, individual JWT claims are not accessible through
struct field lookups. You need to use one of the getter methods.

This is because this library takes the stance that the end user is fully capable
and even willing to shoot themselves on the foot when presented with a lax
API. By making sure that users do not have access to open structs, we can protect
users from doing silly things like creating _incomplete_ structs, or access the
structs concurrently without any protection. This structure also allows
us to put extra smarts in the structs, such as doing the right thing when
you want to parse / write custom fields (this module does not require the user
to specify alternate structs to parse objects with custom fields)

In the end I think it comes down to your usage pattern, and priorities.
Some general guidelines that come to mind are:

* If you want a single library to handle everything JWx, such as using JWE, JWK, JWS, handling [auto-refreshing JWKs](https://github.com/lestrrat-go/jwx/tree/v2/blob/main/docs/04-jwk.md#auto-refreshing-remote-keys), use this module.
* If you want to honor all possible custom fields transparently, use this module.
* If you want a standardized clean API, use this module.

Otherwise, feel free to choose something else.

# Contributions

## Issues

For bug reports and feature requests, please try to follow the issue templates as much as possible.
For either bug reports or feature requests, failing tests are even better.

## Pull Requests

Please make sure to include tests that excercise the changes you made.

If you are editing auto-generated files (those files with the `_gen.go` suffix, please make sure that you do the following:

1. Edit the generator, not the generated files (e.g. internal/cmd/genreadfile/main.go)
2. Run `make generate` (or `go generate`) to generate the new code
3. Commit _both_ the generator _and_ the generated files

## Discussions / Usage

Please try [discussions](https://github.com/lestrrat-go/jwx/tree/v2/discussions) first.

# Related Modules

* [github.com/lestrrat-go/echo-middileware-jwx](https://github.com/lestrrat-go/echo-middleware-jwx) - Sample Echo middleware
* [github.com/jwx-go/crypto-signer/gcp](https://github.com/jwx-go/crypto-signer/tree/main/gcp) - GCP KMS wrapper that implements [`crypto.Signer`](https://pkg.go.dev/crypto#Signer)
* [github.com/jwx-go/crypto-signer/aws](https://github.com/jwx-go/crypto-signer/tree/main/aws) - AWS KMS wrapper that implements [`crypto.Signer`](https://pkg.go.dev/crypto#Signer)

# Credits

* Initial work on this library was generously sponsored by HDE Inc (https://www.hde.co.jp)
* Lots of code, especially JWE was initially taken from go-jose library (https://github.com/square/go-jose)
* Lots of individual contributors have helped this project over the years. Thank each and everyone of you very much.

