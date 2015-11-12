# go-jwx - Implementation of various JWx technologies

[![Build Status](https://travis-ci.org/lestrrat/go-jwx.svg?branch=master)](https://travis-ci.org/lestrrat/go-jwx)
[![GoDoc](https://godoc.org/github.com/lestrrat/go-jwx?status.svg)](https://godoc.org/github.com/lestrrat/go-jwx)

## Synopsis

### JWT

See the examples here as well: https://godoc.org/github.com/lestrrat/go-jwx/jwt#pkg-examples

```
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

```
import(
  "io/ioutil"
  "log"
  "net/http"
  
  "github.com/lestrrat/go-jwx/jwk"
)

func main() {
  res, err := http.Get("https://foobar.domain/jwk.json")
  if err != nil {
    log.Printf("failed to make HTTP request: %s", err)
    return
  }

  buf, err := ioutil.ReadAll(res.Body)
  if err != nil {
    log.Printf("failed to read response body: %s", err)
    return
  }

  set, err := jwk.Parse(buf)
  if err != nil {
    log.Printf("failed to parse JWK: %s", err)
    return
  }

  // If you KNOW you have exactly one key, you can just
  // use set.Keys[0]
  keys := set.LoookupKeyID("mykey")
  if len(keys) == 0 {
    log.Printf("failed to lookup key: %s", err)
    return
  }

  // Assuming RsaPublicKey...
  key := keys[0].(\*jwk.RsaPublicKey)

  pubkey := key.PublicKey()
  // Use pubkey for jws.Verify() or whatever
}
```

### JWS

See the examples here as well: https://godoc.org/github.com/lestrrat/go-jwx/jws#pkg-examples

```
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

  rsasign, err := jws.NewRsaSign(jwa.RS256, privkey)
  if err != nil {
    log.Printf("failed to create RSA signer: %s", err)
    return
  }

  // TODO: rename from NewMultiSigner
  s := jws.NewSigner(rsasign)
  msg, err := s.Sign("Lorem Ipsum")
  if err != nil {
    log.Printf("failed to created JWS message: %s", err)
    return
  }

  v, err := jws.NewRsaVerify(jwa.RS256, &privkey.PublicKey)
  if err != nil {
    log.Printf("failed to create RSA verifier: %s", err)
    return
  }

  if err := v.Verify(msg); err != nil {
    log.Printf("failed to verify message: %s", err)
    return
  }

  log.Printf("signed message verified!")
}
```

### JWE

See the examples here as well: https://godoc.org/github.com/lestrrat/go-jwx/jwe#pkg-examples

```
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

  c, err := jwe.NewAesCrypt(jwa.A128CBC_HS256)
  if err != nil {
    log.Printf("failed to create content encrypter: %s", err)
    return
  }

  k := NewRSAKeyEncrypt(jwa.RSA1_5, &privkey.PublicKey)
  kg := NewRandomKeyGenerate(c.KeySize())

  e := NewEncrypt(c, kg, k)
  msg, err := e.Encrypt([]byte("Lorem Ipsum"))
  if err != nil {
    log.Printf("failed to encrypt payload: %s", err)
    return
  }

  decrypted, err := jwe.DecryptMessage(msg, privkey)
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

## Why?

My goal was to write a server that heavily uses JWK and JWT. At first glance
the libraries that already exist seemed sufficient, but soon I realized that

1. To completely implement the protocols, I needed the entire JWT, JWK, JWS, JWE (and JWA, by necessity).
2. Most of the libraries that existed only deal with a the client side, and hence the subset of the various JWx specifications that were necessary to implement their specific needs

For example, a certain library looke like it had most of JWS, JWE, JWK covered, but then it lacked the ability to include private claims in its JWT responses.

The other library had support of all the private claims, but completely lacked
in its flexibility to generate various different response formats.

So here's go-jwx. As of this writing (Nov 2015), it's still lacking a few of the algorithms that are supposed to be supported by these formats, but in general you should be able to do pretty much everything allowed in the speficiations.

## Contributions

PRs welcome!
