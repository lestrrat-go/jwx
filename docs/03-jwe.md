# Working with JWE

In this document we describe how to work with JWK using `github.com/lestrrat-go/jwx/v2/jwe`

* [Parsing](#parsing)
  * [Parse a JWE message stored in memory](#parse-a-jwe-message-stored-in-memory)
  * [Parse a JWE message stored in a file](#parse-a-jwe-message-stored-in-a-file)
* [Encrypting](#encrypting)
  * [Generating a JWE message in compact serialization format](#generating-a-jwe-message-in-compact-serialization-format)
  * [Generating a JWE message in JSON serialization format](#generating-a-jwe-message-in-json-serialization-format)
  * [Generating a JWE message with detached payload](#generating-a-jwe-message-with-detached-payload)
  * [Including arbitrary headers](#including-arbitrary-headers)
* [Decrypting](#decryptingG)
  * [Decrypting using a single key](#decrypting-using-a-single-key)
  * [Decrypting using a JWKS](#decrypting-using-a-jwks)

# Parsing

Parsing a JWE message means taking either a JWE message serialized in JSON or Compact form and loading it into a `jwe.Message` object. No decryption is performed, and therefore you cannot access the raw payload as when you use `jwe.Decrypt()` to decrypt the message.

Also, be aware that a `jwe.Message` is not meant to be used for either decryption nor encryption. It is only provided so that it can be inspected -- there is no way to decrypt or sign using an already parsed `jwe.Message`.

## Parse a JWE message stored in memory

You can parse a JWE message in memory stored as `[]byte` into a [`jwe.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwe#Message) object. In this mode, there is no decryption performed.

<!-- INCLUDE(examples/jwe_parse_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwe"
)

func ExampleJWE_Parse() {
  const src = `eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.KrFTaMKVY_iUKYYk905QjbUf_fpBXvXCzIAfbPoPMGViDzxtgz5qnch8waV7wraVDfzpW7JfPOw6Nz_-XRwN3Vbud48bRYFw92GkC0M6kpKFpl_xgZxGN47ggNk9hzgqd7mFCuyufeYdn5c2fPoRZAV4UxvakLozEYcQo-eZaFmoYS4pyoC-IKKRikobW8n__LksMzXc_Vps1axn5kdpxsKQ4k1oayvUrgWX2PMxKn_TcLEKHtCN7qRlJ5hkKbZAXAdd34zGWcFV5gc1tcLs6HFhnebo8GUgItTYWBKSKzF6MyLJNRSUPFVq9q-Jxi1juXIlDrv_7rHVsdokQmBfvA.bK7z7Z3gEzFDgDQvNen0Ww.2hngnAVrmucUpJKLgIzYcg.CHs3ZP7JtG430Dl9YAKLMAl`

  msg, err := jwe.Parse([]byte(src))
  if err != nil {
    fmt.Printf("failed to parse JWE message: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(msg)
  // OUTPUT:
  // {"ciphertext":"2hngnAVrmucUpJKLgIzYcg","encrypted_key":"KrFTaMKVY_iUKYYk905QjbUf_fpBXvXCzIAfbPoPMGViDzxtgz5qnch8waV7wraVDfzpW7JfPOw6Nz_-XRwN3Vbud48bRYFw92GkC0M6kpKFpl_xgZxGN47ggNk9hzgqd7mFCuyufeYdn5c2fPoRZAV4UxvakLozEYcQo-eZaFmoYS4pyoC-IKKRikobW8n__LksMzXc_Vps1axn5kdpxsKQ4k1oayvUrgWX2PMxKn_TcLEKHtCN7qRlJ5hkKbZAXAdd34zGWcFV5gc1tcLs6HFhnebo8GUgItTYWBKSKzF6MyLJNRSUPFVq9q-Jxi1juXIlDrv_7rHVsdokQmBfvA","header":{"alg":"RSA1_5"},"iv":"bK7z7Z3gEzFDgDQvNen0Ww","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","tag":"CHs3ZP7JtG430Dl9YAKLMAk"}
}
```
source: [examples/jwe_parse_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwe_parse_example_test.go)
<!-- END INCLUDE -->

## Parse a JWE message stored in a file

To parse a JWE stored in a file, use [`jwe.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwe#ReadFile). [`jwe.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwe#ReadFile) accepts the same options as [`jwe.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwe#Parse).

<!-- INCLUDE(examples/jwe_readfile_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwe"
)

func ExampleJWE_ReadFile() {
  const src = `eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.KrFTaMKVY_iUKYYk905QjbUf_fpBXvXCzIAfbPoPMGViDzxtgz5qnch8waV7wraVDfzpW7JfPOw6Nz_-XRwN3Vbud48bRYFw92GkC0M6kpKFpl_xgZxGN47ggNk9hzgqd7mFCuyufeYdn5c2fPoRZAV4UxvakLozEYcQo-eZaFmoYS4pyoC-IKKRikobW8n__LksMzXc_Vps1axn5kdpxsKQ4k1oayvUrgWX2PMxKn_TcLEKHtCN7qRlJ5hkKbZAXAdd34zGWcFV5gc1tcLs6HFhnebo8GUgItTYWBKSKzF6MyLJNRSUPFVq9q-Jxi1juXIlDrv_7rHVsdokQmBfvA.bK7z7Z3gEzFDgDQvNen0Ww.2hngnAVrmucUpJKLgIzYcg.CHs3ZP7JtG430Dl9YAKLMAl`

  f, err := os.CreateTemp(``, `jwe_readfile_example-*.jwe`)
  if err != nil {
    fmt.Printf("failed to create temporary file: %s\n", err)
    return
  }
  defer os.Remove(f.Name())

  f.Write([]byte(src))
  f.Close()

  msg, err := jwe.ReadFile(f.Name())
  if err != nil {
    fmt.Printf("failed to parse JWE message from file %q: %s\n", f.Name(), err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(msg)
  // OUTPUT:
  // {"ciphertext":"2hngnAVrmucUpJKLgIzYcg","encrypted_key":"KrFTaMKVY_iUKYYk905QjbUf_fpBXvXCzIAfbPoPMGViDzxtgz5qnch8waV7wraVDfzpW7JfPOw6Nz_-XRwN3Vbud48bRYFw92GkC0M6kpKFpl_xgZxGN47ggNk9hzgqd7mFCuyufeYdn5c2fPoRZAV4UxvakLozEYcQo-eZaFmoYS4pyoC-IKKRikobW8n__LksMzXc_Vps1axn5kdpxsKQ4k1oayvUrgWX2PMxKn_TcLEKHtCN7qRlJ5hkKbZAXAdd34zGWcFV5gc1tcLs6HFhnebo8GUgItTYWBKSKzF6MyLJNRSUPFVq9q-Jxi1juXIlDrv_7rHVsdokQmBfvA","header":{"alg":"RSA1_5"},"iv":"bK7z7Z3gEzFDgDQvNen0Ww","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","tag":"CHs3ZP7JtG430Dl9YAKLMAk"}
}
```
source: [examples/jwe_readfile_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwe_readfile_example_test.go)
<!-- END INCLUDE -->

# Encrypting

## Generating a JWE message in compact serialization format

To encrypt an arbitrary payload as a JWE message in compact serialization format, use `jwt.Encrypt()`.

Note that this would be [slightly different if you are encrypting JWTs](01-jwt.md#serialize-using-jws), as you would be
using functions from the `jwt` package instead of `jws`.

<!-- INCLUDE(examples/jwe_encrypt_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwe"
  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWE_Encrypt() {
  rawprivkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to create raw private key: %s\n", err)
    return
  }
  privkey, err := jwk.FromRaw(rawprivkey)
  if err != nil {
    fmt.Printf("failed to create private key: %s\n", err)
    return
  }

  pubkey, err := privkey.PublicKey()
  if err != nil {
    fmt.Printf("failed to create public key:%s\n", err)
    return
  }

  const payload = `Lorem ipsum`
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP, pubkey))
  if err != nil {
    fmt.Printf("failed to encrypt payload: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, privkey))
  if err != nil {
    fmt.Printf("failed to decrypt payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Lorem ipsum
}
```
source: [examples/jwe_encrypt_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwe_encrypt_example_test.go)
<!-- END INCLUDE -->

## Generating a JWE message in JSON serialization format

Generally the only time you need to use a JSON serialization format is when you have to generate multiple recipients (encrypted keys) for a given payload using multiple encryption algorithms and keys.

When this need arises, use the [`jwe.Encrypt()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Encrypt) function with the `jwe.WithJSON()` option and multiple `jwe.WithKey()` options:

<!-- INCLUDE(examples/jwe_encrypt_json_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwe"
  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWE_EncryptJSON() {
  rawprivkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to create raw private key: %s\n", err)
    return
  }
  privkey, err := jwk.FromRaw(rawprivkey)
  if err != nil {
    fmt.Printf("failed to create private key: %s\n", err)
    return
  }

  pubkey, err := privkey.PublicKey()
  if err != nil {
    fmt.Printf("failed to create public key:%s\n", err)
    return
  }

  const payload = `Lorem ipsum`
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithJSON(), jwe.WithKey(jwa.RSA_OAEP, pubkey))
  if err != nil {
    fmt.Printf("failed to encrypt payload: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, privkey))
  if err != nil {
    fmt.Printf("failed to decrypt payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Lorem ipsum
}

func ExampleJWE_EncryptJSONMulti() {
  var privkeys []jwk.Key
  var pubkeys []jwk.Key

  for i := 0; i < 3; i++ {
    rawprivkey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
      fmt.Printf("failed to create raw private key: %s\n", err)
      return
    }
    privkey, err := jwk.FromRaw(rawprivkey)
    if err != nil {
      fmt.Printf("failed to create private key: %s\n", err)
      return
    }
    privkeys = append(privkeys, privkey)

    pubkey, err := privkey.PublicKey()
    if err != nil {
      fmt.Printf("failed to create public key:%s\n", err)
      return
    }
    pubkeys = append(pubkeys, pubkey)
  }

  options := []jwe.EncryptOption{jwe.WithJSON()}
  for _, key := range pubkeys {
    options = append(options, jwe.WithKey(jwa.RSA_OAEP, key))
  }

  const payload = `Lorem ipsum`
  encrypted, err := jwe.Encrypt([]byte(payload), options...)
  if err != nil {
    fmt.Printf("failed to encrypt payload: %s\n", err)
    return
  }

  for _, key := range privkeys {
    decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, key))
    if err != nil {
      fmt.Printf("failed to decrypt payload: %s\n", err)
      return
    }
    fmt.Printf("%s\n", decrypted)
  }
  // OUTPUT:
  // Lorem ipsum
  // Lorem ipsum
  // Lorem ipsum
}
```
source: [examples/jwe_encrypt_json_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwe_encrypt_json_example_test.go)
<!-- END INCLUDE -->

## Including arbitrary headers

By default, only some header fields are included in the result from `jwe.Encrypt()`.

For global protected headers, you can use the `jwe.WithProtectedHeaders()` option.

In order to provide extra headers to the encrypted message such as `apu` and `apv`, you will need to use
`jwe.WithKey()` option with the `jwe.WithPerRecipientHeaders()` suboption.


<!-- INCLUDE(examples/jwe_encrypt_with_headers_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/internal/json"
  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwe"
)

func ExampleJWE_SignWithHeaders() {
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to create private key: %s\n", err)
    return
  }
  const payload = "Lorem ipsum"

  hdrs := jwe.NewHeaders()
  hdrs.Set(`x-example`, true)
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP, privkey.PublicKey, jwe.WithPerRecipientHeaders(hdrs)))
  if err != nil {
    fmt.Printf("failed to encrypt payload: %s\n", err)
    return
  }

  msg, err := jwe.Parse(encrypted)
  if err != nil {
    fmt.Printf("failed to parse message: %s\n", err)
    return
  }

  // NOTE: This is a bit tricky. Even though we specified a per-recipient
  // header when executing jwe.Encrypt, the headers end up being in the
  // global protected headers section. This is... by the books. JWE
  // in Compact serialization asks us to shove the per-recipient
  // headers in the protected header section, because there is nowhere
  // else to store this information.
  //
  // If this were a full JWE JSON message, you might have to juggle
  // between the global protected headers, global unprotected headers,
  // and per-recipient unprotected headers
  json.NewEncoder(os.Stdout).Encode(msg.ProtectedHeaders())

  // OUTPUT:
  // {"alg":"RSA-OAEP","enc":"A256GCM","x-example":true}
}
```
source: [examples/jwe_encrypt_with_headers_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwe_encrypt_with_headers_example_test.go)
<!-- END INCLUDE -->

# Decrypting

## Decrypting using a single key

To decrypt a JWE message using a single key, use `jwe.Decrypt()` with the `jwe.WithKey()` option.
It will automatically do the right thing whether it's serialized in compact form or JSON form.

The `alg` must be explicitly specified.

<!-- INCLUDE(examples/jwe_decrypt_with_key_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwe"
)

func ExampleJWE_VerifyWithKey() {
  const payload = "Lorem ipsum"
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP, jwkRSAPublicKey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, jwkRSAPrivateKey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Lorem ipsum
}
```
source: [examples/jwe_decrypt_with_key_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwe_decrypt_with_key_example_test.go)
<!-- END INCLUDE -->

## Decrypting using a JWKS

To decrypt a payload using JWKS, by default you will need your payload and JWKS to have matching `alg` field.

The `alg` field's requirement is the same for using a single key. See "[Why don't you automatically infer the algorithm for `jwe.Decrypt`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsdecrypt-)"

Note that unlike in JWT, the `kid` is not required by default, although you _can_ make it so
by passing `jwe.WithRequireKid(true)`.

For more discussion on why/how `alg`/`kid` values work, please read the [relevant section in the JWT documentation](01-jwt.md#parse-and-decrypt-a-jwt-with-a-key-set-matching-kid)

<!-- INCLUDE(examples/jwe_decrypt_with_keyset_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwa"
  "github.com/lestrrat-go/jwx/v2/jwe"
  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWE_VerifyWithJWKSet() {
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to create private key: %s\n", err)
    return
  }
  const payload = "Lorem ipsum"
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP, privkey.PublicKey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }

  // Create a JWK Set
  set := jwk.NewSet()
  // Add some bogus keys
  k1, _ := jwk.FromRaw([]byte("abracadabra"))
  set.AddKey(k1)
  k2, _ := jwk.FromRaw([]byte("opensesame"))
  set.AddKey(k2)
  // Add the real thing
  k3, _ := jwk.FromRaw(privkey)
  k3.Set(jwk.AlgorithmKey, jwa.RSA_OAEP)
  set.AddKey(k3)

  // Up to this point, you probably will replace with a simple jwk.Fetch()

  if _, err := jwe.Decrypt(encrypted, jwe.WithKeySet(set, jwe.WithRequireKid(false))); err != nil {
    fmt.Printf("Failed to decrypt using jwk.Set: %s", err)
  }

  // OUTPUT:
}
```
source: [examples/jwe_decrypt_with_keyset_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwe_decrypt_with_keyset_example_test.go)
<!-- END INCLUDE -->
