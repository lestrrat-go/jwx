# github.com/lestrrat-go/jwx/v4 [![CI](https://github.com/lestrrat-go/jwx/actions/workflows/ci.yml/badge.svg)](https://github.com/lestrrat-go/jwx/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/v4.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4)

Go module implementing various JWx (JWA/JWE/JWK/JWS/JWT, otherwise known as JOSE) technologies.

If you are using this module in your product or your company, please add your product and/or company name in the [Wiki](https://github.com/lestrrat-go/jwx/wiki/Users)! It really helps keeping up our motivation.

# Requirements

* Go 1.26 or later
* `GOEXPERIMENT=jsonv2`

# Install

```
go get github.com/lestrrat-go/jwx/v4
```

# Migrating from v3

If you are migrating from `github.com/lestrrat-go/jwx/v3`, see [`MIGRATION.md`](MIGRATION.md) for a step-by-step guide with before/after code examples. For a complete list of breaking changes and new features, see [`Changes-v4.md`](Changes-v4.md).

# Features

| Feature | Description |
|---------|-------------|
| **Complete JWA/JWE/JWK/JWS/JWT coverage** | Not just JWT + minimum tool set. Supports JWS messages with multiple signatures (compact and JSON serialization), JWS with detached payload, JWS with unencoded payload (RFC 7797), JWE messages with multiple recipients (compact and JSON serialization). Most operations work with either JWK or raw keys (e.g. `*rsa.PrivateKey`, `*ecdsa.PrivateKey`). |
| **Opinionated, uniform API** | Everything is symmetric and follows a standard convention: `jws.Parse`/`Verify`/`Sign`, `jwe.Parse`/`Encrypt`/`Decrypt`. Arguments are organized as explicit required parameters and optional `WithXXXX()` style options. |
| **Post-quantum cryptography** | Supports ML-KEM, ML-DSA, and HPKE. |
| **Extension module architecture** | Opt-in features via extension modules. See [Extension Modules](docs/10-extensions.md). |
| **JWK Caching** | [`jwkcache`](https://github.com/jwx-go/jwkcache) extension to always keep a JWKS up-to-date. |
| **Bazel Support** | [Bazel](https://bazel.build)-ready. |

# SYNOPSIS

<!-- INCLUDE(examples/jwx_readme_example_test.go) -->
```go
package examples_test

import (
  "bytes"
  "fmt"
  "net/http"
  "time"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
  "github.com/lestrrat-go/jwx/v4/jwk"
  "github.com/lestrrat-go/jwx/v4/jws"
  "github.com/lestrrat-go/jwx/v4/jwt"
)

func Example() {
  // Parse, serialize, slice and dice JWKs!
  privkey, err := jwk.ParseKey(jsonRSAPrivateKey)
  if err != nil {
    fmt.Printf("failed to parse JWK: %s\n", err)
    return
  }

  pubkey, err := jwk.PublicKeyOf(privkey)
  if err != nil {
    fmt.Printf("failed to get public key: %s\n", err)
    return
  }

  // Work with JWTs!
  {
    // Build a JWT!
    tok, err := jwt.NewBuilder().
      Issuer(`github.com/lestrrat-go/jwx`).
      IssuedAt(time.Now()).
      Build()
    if err != nil {
      fmt.Printf("failed to build token: %s\n", err)
      return
    }

    // Sign a JWT!
    signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privkey))
    if err != nil {
      fmt.Printf("failed to sign token: %s\n", err)
      return
    }

    // Verify a JWT!
    {
      verifiedToken, err := jwt.Parse(signed, jwt.WithKey(jwa.RS256(), pubkey))
      if err != nil {
        fmt.Printf("failed to verify JWS: %s\n", err)
        return
      }
      _ = verifiedToken
    }

    // Work with *http.Request!
    {
      req, _ := http.NewRequest(http.MethodGet, `https://github.com/lestrrat-go/jwx`, nil)
      req.Header.Set(`Authorization`, fmt.Sprintf(`Bearer %s`, signed))

      verifiedToken, err := jwt.ParseRequest(req, jwt.WithKey(jwa.RS256(), pubkey))
      if err != nil {
        fmt.Printf("failed to verify token from HTTP request: %s\n", err)
        return
      }
      _ = verifiedToken
    }
  }

  // Encrypt and Decrypt arbitrary payload with JWE!
  {
    encrypted, err := jwe.Encrypt(payloadLoremIpsum, jwe.WithKey(jwa.RSA_OAEP(), jwkRSAPublicKey))
    if err != nil {
      fmt.Printf("failed to encrypt payload: %s\n", err)
      return
    }

    decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP(), jwkRSAPrivateKey))
    if err != nil {
      fmt.Printf("failed to decrypt payload: %s\n", err)
      return
    }

    if !bytes.Equal(decrypted, payloadLoremIpsum) {
      fmt.Printf("verified payload did not match\n")
      return
    }
  }

  // Sign and Verify arbitrary payload with JWS!
  {
    signed, err := jws.Sign(payloadLoremIpsum, jws.WithKey(jwa.RS256(), jwkRSAPrivateKey))
    if err != nil {
      fmt.Printf("failed to sign payload: %s\n", err)
      return
    }

    verified, err := jws.Verify(signed, jws.WithKey(jwa.RS256(), jwkRSAPublicKey))
    if err != nil {
      fmt.Printf("failed to verify payload: %s\n", err)
      return
    }

    if !bytes.Equal(verified, payloadLoremIpsum) {
      fmt.Printf("verified payload did not match\n")
      return
    }
  }
  // OUTPUT:
}
```
source: [examples/jwx_readme_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwx_readme_example_test.go)
<!-- END INCLUDE -->

# Documentation

* [API Reference](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4)
* [How-to Documentation](./docs)
* [Runnable Examples](https://github.com/jwx-go/examples)
* [Extension Modules](docs/10-extensions.md)

# Packages and Standards

This module implements the following specifications:

| Package | Specification |
|---------|---------------|
| [jwa](./jwa) | [RFC 7518](https://tools.ietf.org/html/rfc7518) (JSON Web Algorithms) |
| [jwk](./jwk) | [RFC 7517](https://tools.ietf.org/html/rfc7517) (JSON Web Key), [RFC 7638](https://tools.ietf.org/html/rfc7638) (JWK Thumbprint), [RFC 8037](https://tools.ietf.org/html/rfc8037) (CFRG Curves) |
| [jws](./jws) | [RFC 7515](https://tools.ietf.org/html/rfc7515) (JSON Web Signature), [RFC 7797](https://tools.ietf.org/html/rfc7797) (Unencoded Payload) |
| [jwe](./jwe) | [RFC 7516](https://tools.ietf.org/html/rfc7516) (JSON Web Encryption), [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/) (HPKE) |
| [jwt](./jwt) | [RFC 7519](https://tools.ietf.org/html/rfc7519) (JSON Web Token) |

Additionally supported via the main module or [extension modules](docs/10-extensions.md):

| Specification | Support |
|---------------|---------|
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM) | JWE key encapsulation via [`github.com/jwx-go/mlkem`](https://github.com/jwx-go/mlkem): ML-KEM-768, ML-KEM-1024, hybrid variants (draft-ietf-jose-pqc-kem) |
| [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA) | JWS signatures via [`github.com/jwx-go/mldsa`](https://github.com/jwx-go/mldsa) |


## History

My goal was to write a server that heavily uses JWK and JWT. At first glance
the libraries that already exist seemed sufficient, but soon I realized that

1. To completely implement the protocols, I needed the entire JWT, JWK, JWS, JWE (and JWA, by necessity).
2. Most of the libraries that existed only deal with a subset of the various JWx specifications that were necessary to implement their specific needs

For example, a certain library looks like it had most of JWS, JWE, JWK covered, but then it lacked the ability to include private claims in its JWT responses. Another library had support of all the private claims, but completely lacked in its flexibility to generate various different response formats.

Because I was writing the server side (and the client side for testing), I needed the *entire* JOSE toolset to properly implement my server, **and** they needed to be *flexible* enough to fulfill the entire spec that I was writing.

So here's `github.com/lestrrat-go/jwx/v4`. This library is extensible, customizable, and hopefully well organized to the point that it is easy for you to slice and dice it.

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
implementing the entirety of JWS/JWE/JWK, which this library does.

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

* If you want a single library to handle everything JWx, such as using JWE, JWK, JWS, handling [auto-refreshing JWKs](https://github.com/jwx-go/jwkcache), use this module.
* If you want to honor all possible custom fields transparently, use this module.
* If you want a standardized clean API, use this module.

Otherwise, feel free to choose something else.

# Contributions

## Issues

For bug reports and feature requests, please try to follow the issue templates as much as possible.
For either bug reports or feature requests, failing tests are even better.

## Pull Requests

Please make sure to include tests that exercise the changes you made.

If you are editing auto-generated files (those files with the `_gen.go` suffix, please make sure that you do the following:

1. Edit the generator, not the generated files (e.g. `internal/jwxcodegen/cmd/jwxcodegen/`)
2. Run `make generate` (or `go generate`) to generate the new code
3. Commit _both_ the generator _and_ the generated files

## Discussions / Usage

Please try [discussions](https://github.com/lestrrat-go/jwx/discussions) first.

# Credits

* Initial work on this library was generously sponsored by HDE Inc (https://www.hde.co.jp)
* Lots of code, especially JWE was initially taken from go-jose library (https://github.com/square/go-jose)
* Lots of individual contributors have helped this project over the years. Thank each and everyone of you very much.

# Quid pro quo

If you use this software to build products in a for-profit organization, we ask you to _consider_
contributing back to FOSS in the following manner:

* For every 100 employees (direct hires) of your organization, please consider contributing minimum of $1 every year to either this project, **or** another FOSS projects that this project uses. For example, for 100 employees, we ask you contribute $100 yearly; for 10,000 employees, we ask you contribute $10,000 yearly.
* If possible, please make this information public. You do not need to disclose the amount you are contributing, but please make the information that you are contributing to particular FOSS projects public. For this project, please consider writing your name on the [Wiki](https://github.com/lestrrat-go/jwx/wiki/Users)

This is _NOT_ a licensing term: you are still free to use this software according to the license it
comes with. This clause is only a plea for people to acknowledge the work from FOSS developers whose
work you rely on each and everyday.
