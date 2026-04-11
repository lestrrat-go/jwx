# JWS [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/v4/jws.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws)

Package jws implements JWS as described in [RFC 7515](https://tools.ietf.org/html/rfc7515) and [RFC 7797](https://tools.ietf.org/html/rfc7797). See [Working with JWS](../docs/02-jws.md) for how-to style documentation and examples.

## Supported signature algorithms

| Algorithm                               | Constant in [jwa](../jwa) |
|:----------------------------------------|:-------------------------|
| HMAC using SHA-256                      | jwa.HS256                |
| HMAC using SHA-384                      | jwa.HS384                |
| HMAC using SHA-512                      | jwa.HS512                |
| RSASSA-PKCS-v1.5 using SHA-256          | jwa.RS256                |
| RSASSA-PKCS-v1.5 using SHA-384          | jwa.RS384                |
| RSASSA-PKCS-v1.5 using SHA-512          | jwa.RS512                |
| ECDSA using P-256 and SHA-256           | jwa.ES256                |
| ECDSA using P-384 and SHA-384           | jwa.ES384                |
| ECDSA using P-521 and SHA-512           | jwa.ES512                |
| RSASSA-PSS using SHA256 and MGF1-SHA256 | jwa.PS256                |
| RSASSA-PSS using SHA384 and MGF1-SHA384 | jwa.PS384                |
| RSASSA-PSS using SHA512 and MGF1-SHA512 | jwa.PS512                |
| EdDSA using Ed25519                     | jwa.EdDSAEd25519         |
| EdDSA (deprecated by RFC 9864)          | jwa.EdDSA                |

Additional algorithms available via [extension modules](../docs/10-extensions.md): ES256K ([`github.com/jwx-go/es256k`](https://github.com/jwx-go/es256k)), Ed448 ([`github.com/jwx-go/ed448`](https://github.com/jwx-go/ed448)), ML-DSA ([`github.com/jwx-go/mldsa`](https://github.com/jwx-go/mldsa)).

