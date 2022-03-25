# JWK [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/v2/jwk.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk)

Package jwk implements JWK as described in [RFC7517](https://tools.ietf.org/html/rfc7517).
If you are looking to use JWT wit JWKs, look no further than [github.com/lestrrat-go/jwx](../jwt).

* Parse and work with RSA/EC/Symmetric/OKP JWK types
  * Convert to and from JSON
  * Convert to and from raw key types (e.g. *rsa.PrivateKey)
* Ability to keep a JWKS fresh using *jwk.AutoRefersh

## Supported key types:

| kty | Curve                   | Go Key Type                                   |
|:----|:------------------------|:----------------------------------------------|
| RSA | N/A                     | rsa.PrivateKey / rsa.PublicKey (2)            |
| EC  | P-256<br>P-384<br>P-521<br>secp256k1 (1) | ecdsa.PrivateKey / ecdsa.PublicKey (2)        |
| oct | N/A                     | []byte                                        |
| OKP | Ed25519 (1)             | ed25519.PrivateKey / ed25519.PublicKey (2)    |
|     | X25519 (1)              | (jwx/)x25519.PrivateKey / x25519.PublicKey (2)|

* Note 1: Experimental
* Note 2: Either value or pointers accepted (e.g. rsa.PrivateKey or *rsa.PrivateKey)

# Documentation

Please read the [API reference](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk), or
the how-to style documentation on how to use JWK can be found in the [docs directory](../docs/04-jwk.md).

# Auto-Refresh a key during a long running process

<!-- INCLUDE(examples/jwk_cache_example_test.go) -->
<!-- END INCLUDE -->

Parse and use a JWK key:

<!-- INCLUDE(examples/jwk_example_test.go) -->
<!-- END INCLUDE -->
