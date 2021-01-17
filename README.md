# jwx

Implementation of various JWx technologies

![](https://github.com/lestrrat-go/jwx/workflows/CI/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx)
[![codecov.io](http://codecov.io/github/lestrrat-go/jwx/coverage.svg?branch=master)](http://codecov.io/github/lestrrat-go/jwx?branch=master)

## Status

### Done

PR/issues welcome.

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

## Notes for users of pre-1.0.0 release

The API has been reworked quite substantially between pre- and post 1.0.0 releases. Please check out the [Changes](./Changes) file (or the [diff](https://github.com/lestrrat-go/jwx/compare/v0.9.2...v1.0.0), if you are into that sort of thing)

## JWT

[![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/jwt.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt)

Package [github.com/lestrrat-go/jwx/jwt](./jwt) implements JSON Web Tokens as described in [RFC7519](https://tools.ietf.org/html/rfc7519).

* Convenience methods for oft-used keys ("aud", "sub", "iss", etc)
* Ability to Get/Set arbitrary keys
* Conversion to and from JSON
* Generate signed tokens
* Verify signed tokens
* Extra support for OpenID tokens via [github.com/lestrrat-go/jwx/jwt/openid](./jwt/openid)

Examples are located in the examples directory ([jwt_example_test.go](./examples/jwt_example_test.go))

### JWK

Examples are located in the examples directory ([jwk_example_test.go](./examples/jwk_example_test.go))

Create a JWK file from RSA public key:

```go
import(
  "crypto/rand"
  "crypto/rsa"
  "encoding/json"
  "log"
  "os"

  "github.com/lestrrat-go/jwx/jwk"
)

func main() {
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    log.Printf("failed to generate private key: %s", err)
    return
  }

  key, err := jwk.New(&privkey.PublicKey)
  if err != nil {
    log.Printf("failed to create JWK: %s", err)
    return
  }

  jsonbuf, err := json.MarshalIndent(key, "", "  ")
  if err != nil {
    log.Printf("failed to generate JSON: %s", err)
    return
  }

  os.Stdout.Write(jsonbuf)
}
```

Parse and use a JWK key:

```go

import (
  "encoding/json"
  "log"

  "github.com/lestrrat-go/jwx/jwk"
)

func main() {
  set, err := jwk.FetchHTTP("https://www.googleapis.com/oauth2/v3/certs")
  if err != nil {
    log.Printf("failed to parse JWK: %s", err)
    return
  }

  // Key sets can be serialized back to JSON
  {
    jsonbuf, err := json.Marshal(set)
    if err != nil {
      log.Printf("failed to marshal key set into JSON: %s", err)
      return
    }
    log.Printf("%s", jsonbuf)
  }

  for it := set.Iterate(context.Background()); it.Next(context.Background()); {
    pair := it.Pair()
    key := pair.Value.(jwk.Key)

    var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
    if err := key.Raw(&rawkey); err != nil {
      log.Printf("failed to create public key: %s", err)
      return
    }
    // Use rawkey for jws.Verify() or whatever.
    _ = rawkey

    // You can create jwk.Key from a raw key, too
    fromRawKey, err := jwk.New(rawkey)


    // Keys can be serialized back to JSON
    jsonbuf, err := json.Marshal(key)
    if err != nil {
      log.Printf("failed to marshal key into JSON: %s", err)
      return
    }
    log.Printf("%s", jsonbuf)

    // If you know the underlying Key type (RSA, EC, Symmetric), you can
    // create an empy instance first
    //    key := jwk.NewRSAPrivateKey()
    // ..and then use json.Unmarshal
    //    json.Unmarshal(key, jsonbuf)
    //
    // but if you don't know the type first, you have an abstract type
    // jwk.Key, which can't be used as the first argument to json.Unmarshal
    //
    // In this case, use jwk.Parse()
    fromJsonKey, err := jwk.ParseBytes(jsonbuf)
    if err != nil {
      log.Printf("failed to parse json: %s", err)
      return
    }
    _ = fromJsonKey
    _ = fromRawKey
  }
}
```

Supported key types:

| kty | Curve                   | Go Key Type                                |
|:----|:------------------------|:-------------------------------------------|
| RSA | N/A                     | rsa.PrivateKey / rsa.PublicKey             |
| EC  | P-256<br>P-384<br>P-521 | ecdsa.PrivateKey / ecdsa.PublicKey         |
| oct | N/A                     | []byte                                     |
| OKP | Ed25519 (1)             | ed25519.PrivateKey / ed25519.PublicKey     |
|     | X25519 (1)              | (jwx/)x25519.PrivateKey / x25519.PublicKey |

Note 1: Experimental

### JWS - Verify parse and verify a signed JWT

Examples are located in the examples directory ([jws_example_test.go](./examples/jws_example_test.go))

```go
  token, err := jwt.Parse(bytes.NewReader(payload), jwt.WithKeySet(keyset))
  if err != nil {
    fmt.Printf("failed to parse payload: %s\n", err)
  }
```

### JWS - Sign / verify arbitrary data

```go
import(
  "crypto/rand"
  "crypto/rsa"
  "log"

  "github.com/lestrrat-go/jwx/jwa"
  "github.com/lestrrat-go/jwx/jws"
)

func main() {
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    log.Printf("failed to generate private key: %s", err)
    return
  }

  buf, err := jws.Sign([]byte("Lorem ipsum"), jwa.RS256, privkey)
  if err != nil {
    log.Printf("failed to created JWS message: %s", err)
    return
  }

  // When you receive a JWS message, you can verify the signature
  // and grab the payload sent in the message in one go:
  verified, err := jws.Verify(buf, jwa.RS256, &privkey.PublicKey)
  if err != nil {
    log.Printf("failed to verify message: %s", err)
    return
  }

  log.Printf("signed message verified! -> %s", verified)
}
```

Supported signature algorithms:

| Algorithm                               | Supported? | Constant in go-jwx |
|:----------------------------------------|:-----------|:-------------------|
| HMAC using SHA-256                      | YES        | jwa.HS256          |
| HMAC using SHA-384                      | YES        | jwa.HS384          |
| HMAC using SHA-512                      | YES        | jwa.HS512          |
| RSASSA-PKCS-v1.5 using SHA-256          | YES        | jwa.RS256          |
| RSASSA-PKCS-v1.5 using SHA-384          | YES        | jwa.RS384          |
| RSASSA-PKCS-v1.5 using SHA-512          | YES        | jwa.RS512          |
| ECDSA using P-256 and SHA-256           | YES        | jwa.ES256          |
| ECDSA using P-384 and SHA-384           | YES        | jwa.ES384          |
| ECDSA using P-521 and SHA-512           | YES        | jwa.ES512          |
| RSASSA-PSS using SHA256 and MGF1-SHA256 | YES        | jwa.PS256          |
| RSASSA-PSS using SHA384 and MGF1-SHA384 | YES        | jwa.PS384          |
| RSASSA-PSS using SHA512 and MGF1-SHA512 | YES        | jwa.PS512          |
| EdDSA (1)                               | YES        | jwa.EdDSA          |

Note 1: Experimental

### JWE

Examples are located in the examples directory ([jwe_example_test.go](./examples/jwe_example_test.go))

```go
import(
  "crypto/rand"
  "crypto/rsa"
  "log"

  "github.com/lestrrat-go/jwx/jwa"
  "github.com/lestrrat-go/jwx/jwe"
)

func main() {
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    log.Printf("failed to generate private key: %s", err)
    return
  }

  payload := []byte("Lorem Ipsum")

  encrypted, err := jwe.Encrypt(payload, jwa.RSA1_5, &privkey.PublicKey, jwa.A128CBC_HS256, jwa.NoCompress)
  if err != nil {
    log.Printf("failed to encrypt payload: %s", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted, jwa.RSA1_5, privkey)
  if err != nil {
    log.Printf("failed to decrypt: %s", err)
    return
  }

  if string(decrypted) != "Lorem Ipsum" {
    log.Printf("WHAT?!")
    return
  }
}
```

Supported key encryption algorithm:

| Algorithm                                | Supported? | Constant in go-jwx     |
|:-----------------------------------------|:-----------|:-----------------------|
| RSA-PKCS1v1.5                            | YES        | jwa.RSA1_5             |
| RSA-OAEP-SHA1                            | YES        | jwa.RSA_OAEP           |
| RSA-OAEP-SHA256                          | YES        | jwa.RSA_OAEP_256       |
| AES key wrap (128)                       | YES        | jwa.A128KW             |
| AES key wrap (192)                       | YES        | jwa.A192KW             |
| AES key wrap (256)                       | YES        | jwa.A256KW             |
| Direct encryption                        | YES (1)    | jwa.DIRECT             |
| ECDH-ES                                  | YES (1)    | jwa.ECDH_ES            |
| ECDH-ES + AES key wrap (128)             | YES        | jwa.ECDH_ES_A128KW     |
| ECDH-ES + AES key wrap (192)             | YES        | jwa.ECDH_ES_A192KW     |
| ECDH-ES + AES key wrap (256)             | YES        | jwa.ECDH_ES_A256KW     |
| AES-GCM key wrap (128)                   | YES        | jwa.A128GCMKW          |
| AES-GCM key wrap (192)                   | YES        | jwa.A192GCMKW          |
| AES-GCM key wrap (256)                   | YES        | jwa.A256GCMKW          |
| PBES2 + HMAC-SHA256 + AES key wrap (128) | YES        | jwa.PBES2_HS256_A128KW |
| PBES2 + HMAC-SHA384 + AES key wrap (192) | YES        | jwa.PBES2_HS384_A192KW |
| PBES2 + HMAC-SHA512 + AES key wrap (256) | YES        | jwa.PBES2_HS512_A256KW |

Note 1: Single-recipient only

Supported content encryption algorithm:

| Algorithm                   | Supported? | Constant in go-jwx     |
|:----------------------------|:-----------|:-----------------------|
| AES-CBC + HMAC-SHA256 (128) | YES        | jwa.A128CBC_HS256      |
| AES-CBC + HMAC-SHA384 (192) | YES        | jwa.A192CBC_HS384      |
| AES-CBC + HMAC-SHA512 (256) | YES        | jwa.A256CBC_HS512      |
| AES-GCM (128)               | YES        | jwa.A128GCM            |
| AES-GCM (192)               | YES        | jwa.A192GCM            |
| AES-GCM (256)               | YES        | jwa.A256GCM            |

PRs welcome to support missing algorithms!

## Configuring JSON Parsing

If you want to parse numbers in the incoming JSON objects as json.Number
instead of floats, you can use the following call to globally affect the behavior of JSON parsing.

```go
func init()
  jwx.DecoderSettings(jwx.WithUseNumber(true))
}
```

Do be aware that this has *global* effect. All code that calls in to `encoding/json`
within `jwx` *will* use your settings.

## Other related libraries:

* https://github.com/dgrijalva/jwt-go
* https://github.com/square/go-jose
* https://github.com/coreos/oidc
* https://golang.org/x/oauth2

## Contributions

PRs welcome!

## Credits

* Work on this library was generously sponsored by HDE Inc (https://www.hde.co.jp)
* Lots of code, especially JWE was taken from go-jose library (https://github.com/square/go-jose)
