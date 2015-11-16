# go-jwx - Implementation of various JWx technologies

[![Build Status](https://travis-ci.org/lestrrat/go-jwx.svg?branch=master)](https://travis-ci.org/lestrrat/go-jwx)
[![GoDoc](https://godoc.org/github.com/lestrrat/go-jwx?status.svg)](https://godoc.org/github.com/lestrrat/go-jwx)

## Status

### Done

PR/issues welcome. All needs more docs

* jwt
* jwk
* jwa
* jws
* jwe

### In progress:

* jwe - more algorithms

## Why?

My goal was to write a server that heavily uses JWK and JWT. At first glance
the libraries that already exist seemed sufficient, but soon I realized that

1. To completely implement the protocols, I needed the entire JWT, JWK, JWS, JWE (and JWA, by necessity).
2. Most of the libraries that existed only deal with a subset of the various JWx specifications that were necessary to implement their specific needs

For example, a certain library looke like it had most of JWS, JWE, JWK covered, but then it lacked the ability to include private claims in its JWT responses. Another other library had support of all the private claims, but completely lacked in its flexibility to generate various different response formats.

Because I was writing the server side (and the client side for testing), I needed the entire toolsetto properly implement my server, and also they needed to be flexible.

So here's go-jwx. As of this writing (Nov 2015), it's still lacking a few of the algorithms that are supposed to be supported by these formats, but in general you should be able to do pretty much everything allowed in the speficiations.

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
}
```

### JWK

See the examples here as well: https://godoc.org/github.com/lestrrat/go-jwx/jwk#pkg-examples

```go
import(
  "log"
  
  "github.com/lestrrat/go-jwx/jwk"
)

func main() {
  set, err := jwk.Fetch("https://foobar.domain/jwk.json")
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
  verified, err := jws.Verify(buf, jws.RS256, &privkey.PublicKey)
  if err != nil {
    log.Printf("failed to verify message: %s", err)
    return
  }

  log.Printf("signed message verified! -> %s", verified)
}
```

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


