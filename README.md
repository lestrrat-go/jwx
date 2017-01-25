# go-jwx - Implementation of various JWx technologies

[![Build Status](https://travis-ci.org/lestrrat/go-jwx.svg?branch=master)](https://travis-ci.org/lestrrat/go-jwx)
[![GoDoc](https://godoc.org/github.com/lestrrat/go-jwx?status.svg)](https://godoc.org/github.com/lestrrat/go-jwx)

## Status

### Done

PR/issues welcome.

| Package name                                              | Notes                                           |
|-----------------------------------------------------------|-------------------------------------------------|
| [jwt](https://github.com/lestrrat/go-jwx/tree/master/jwt) | [RFC 7519](https://tools.ietf.org/html/rfc7519) |
| [jwk](https://github.com/lestrrat/go-jwx/tree/master/jwk) | [RFC 7517](https://tools.ietf.org/html/rfc7517) + [RFC 7638](https://tools.ietf.org/html/rfc7638) |
| [jwa](https://github.com/lestrrat/go-jwx/tree/master/jwa) | [RFC 7518](https://tools.ietf.org/html/rfc7518) |
| [jws](https://github.com/lestrrat/go-jwx/tree/master/jws) | [RFC 7515](https://tools.ietf.org/html/rfc7515) |
| [jwe](https://github.com/lestrrat/go-jwx/tree/master/jwe) | [RFC 7516](https://tools.ietf.org/html/rfc7516) |

### In progress:

* jwe - more algorithms

## Why?

My goal was to write a server that heavily uses JWK and JWT. At first glance
the libraries that already exist seemed sufficient, but soon I realized that

1. To completely implement the protocols, I needed the entire JWT, JWK, JWS, JWE (and JWA, by necessity).
2. Most of the libraries that existed only deal with a subset of the various JWx specifications that were necessary to implement their specific needs

For example, a certain library looks like it had most of JWS, JWE, JWK covered, but then it lacked the ability to include private claims in its JWT responses. Another library had support of all the private claims, but completely lacked in its flexibility to generate various different response formats.

Because I was writing the server side (and the client side for testing), I needed the *entire* JOSE toolset to properly implement my server, **and** they needed to be *flexible* enough to fulfill the entire spec that I was writing.

So here's go-jwx. This library is extensible, customizable, and hopefully well organized to the point that it is easy for you to slice and dice it.

As of this writing (Nov 2015), it's still lacking a few of the algorithms for JWE that are described in JWA (which I believe to be less frequently used), but in general you should be able to do pretty much everything allowed in the specifications.

## Synopsis

### JWT

See the examples here as well: https://godoc.org/github.com/lestrrat/go-jwx/jwt#pkg-examples

```go
import(
  "encoding/json"
  "log"

  "github.com/lestrrat/go-jwx/jwt"
)

func main() {
  c := jwt.NewClaimSet()
  c.Set("sub", "123456789")
  c.Set("aud", "foo")
  c.Set("https://github.com/lestrrat", "me")

  buf, err := json.MarshalIndent(c, "", "  ")
  if err != nil {
    log.Printf("failed to generate JSON: %s", err)
    return
  }

  log.Printf("%s", buf)
  log.Printf("sub     -> '%s'", c.Get("sub").(string))
  log.Printf("aud     -> '%v'", c.Get("aud").([]string))
  log.Printf("private -> '%s'", c.Get("https://github.com/lestrrat").(string))

  // Possibly use c.Verify() to verify the claim set
}
```

### JWK

See the examples here as well: https://godoc.org/github.com/lestrrat/go-jwx/jwk#pkg-examples

Create a JWK file from RSA public key:

```go
import(
  "crypto/rand"
  "crypto/rsa"
  "encoding/json"
  "log"
  "os"

  "github.com/lestrrat/go-jwx/jwk"
)

func main() {
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    log.Printf("failed to generate private key: %s", err)
    return
  }

  key, err := jwk.NewRsaPublicKey(&privkey.PublicKey)
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
import(
  "log"

  "github.com/lestrrat/go-jwx/jwk"
)

func main() {
  set, err := jwk.FetchHTTP("https://foobar.domain/jwk.json")
  if err != nil {
    log.Printf("failed to parse JWK: %s", err)
    return
  }

  // If you KNOW you have exactly one key, you can just
  // use set.Keys[0]
  keys := set.LookupKeyID("mykey")
  if len(keys) == 0 {
    log.Printf("failed to lookup key: %s", err)
    return
  }

  key, err := keys[0].Materialize()
  if err != nil {
    log.Printf("failed to create public key: %s", err)
    return
  }

  // Use key for jws.Verify() or whatever
}
```

### JWS

See also `VerifyWithJWK` and `VerifyWithJKU`

```go
import(
  "crypto/rand"
  "crypto/rsa"
  "log"

  "github.com/lestrrat/go-jwx/jwa"
  "github.com/lestrrat/go-jwx/jws"
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

  // When you received a JWS message, you can verify the signature
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

### JWE

See the examples here as well: https://godoc.org/github.com/lestrrat/go-jwx/jwe#pkg-examples

```go
import(
  "crypto/rand"
  "crypto/rsa"
  "log"

  "github.com/lestrrat/go-jwx/jwa"
  "github.com/lestrrat/go-jwx/jwe"
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
| Direct encryption                        | NO         | jwa.DIRECT             |
| ECDH-ES                                  | YES        | jwa.ECDH_ES            |
| ECDH-ES + AES key wrap (128)             | YES        | jwa.ECDH_ES_A128KW     |
| ECDH-ES + AES key wrap (192)             | YES        | jwa.ECDH_ES_A192KW     |
| ECDH-ES + AES key wrap (256)             | YES        | jwa.ECDH_ES_A256KW     |
| AES-GCM key wrap (128)                   | NO         | jwa.A128GCMKW          |
| AES-GCM key wrap (192)                   | NO         | jwa.A192GCMKW          |
| AES-GCM key wrap (256)                   | NO         | jwa.A256GCMKW          |
| PBES2 + HMAC-SHA256 + AES key wrap (128) | NO         | jwa.PBES2_HS256_A128KW |
| PBES2 + HMAC-SHA384 + AES key wrap (192) | NO         | jwa.PBES2_HS384_A192KW |
| PBES2 + HMAC-SHA512 + AES key wrap (256) | NO         | jwa.PBES2_HS512_A256KW |

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
