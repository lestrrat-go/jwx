# Working with JWE

In this document we describe how to work with JWK using `github.com/lestrrat-go/jwx/v4/jwe`

* [Parsing](#parsing)
  * [Parse a JWE message stored in memory](#parse-a-jwe-message-stored-in-memory)
  * [Parse a JWE message stored in a file](#parse-a-jwe-message-stored-in-a-file)
* [Encrypting](#encrypting)
  * [Generating a JWE message in compact serialization format](#generating-a-jwe-message-in-compact-serialization-format)
  * [Generating a JWE message in JSON serialization format](#generating-a-jwe-message-in-json-serialization-format)
  * [Including arbitrary headers](#including-arbitrary-headers)
* [Decrypting](#decrypting)
  * [Decrypting using a single key](#decrypting-using-a-single-key)
  * [Decrypting using a JWKS](#decrypting-using-a-jwks)
* [HPKE (Hybrid Public Key Encryption)](#hpke-hybrid-public-key-encryption)
* [ECDH-ES with X25519](#ecdh-es-with-x25519)
* [Filtering JWE headers](#filtering-jwe-headers)

# Parsing

Parsing a JWE message means taking either a JWE message serialized in JSON or Compact form and loading it into a `jwe.Message` object. No decryption is performed, and therefore you cannot access the raw payload like when you use `jwe.Decrypt()` to decrypt the message.

Also, be aware that a `jwe.Message` is not meant to be used for either decryption nor encryption. It is only provided so that it can be inspected -- there is no way to decrypt or sign using an already parsed `jwe.Message`.

## Parse a JWE message stored in memory

You can parse a JWE message in memory stored as `[]byte` into a [`jwe.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwe#Message) object. In this mode, there is no decryption performed.

<!-- INCLUDE(examples/jwe_parse_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_parse() {
  // A sample compact-serialized JWE produced with alg=RSA-OAEP and
  // enc=A256GCM. The five dot-separated segments are
  // protected-header / encrypted-key / iv / ciphertext / tag.
  const src = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.QoQNICnJzzytxWd9FOy6PgP2Qyh6HAPXWBXSdaWCX7upX_mzXBdR2r6zJgb-8HgAMJ9dXJvTaaoNq6J5JOOZMUprnPy08rwACkKK_lR363C380_LHlYmqDQGPoqUt97m2ZDUgfGDKv7ilw6SAQpGZ7e3eOY4g_qINmJ8HxOUBovV_D335SFGOiPeogYGobzGhnqFdQ3wTAdy_aLFXiN8SYpCwIx_GugrI1x2JzCZ6INV_VVvp6gzYIr6nUNooQt0EwnlrsNlaFHIemFMmNoOHSTKvgXI49ZCVpBSZ3fQEtQPMlq2RB099VCLDTofBTOJvlYo4VPA5uxbs5pHa3ULGg.YWtQIqXd8VYpjBGZ.KmJpIgDVk-c0Ei4.94UMzAd_b8yQJq6e3R2a-g`

  msg, err := jwe.Parse([]byte(src))
  if err != nil {
    fmt.Printf("failed to parse JWE message: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(msg)
  // OUTPUT:
  // {"ciphertext":"KmJpIgDVk-c0Ei4","encrypted_key":"QoQNICnJzzytxWd9FOy6PgP2Qyh6HAPXWBXSdaWCX7upX_mzXBdR2r6zJgb-8HgAMJ9dXJvTaaoNq6J5JOOZMUprnPy08rwACkKK_lR363C380_LHlYmqDQGPoqUt97m2ZDUgfGDKv7ilw6SAQpGZ7e3eOY4g_qINmJ8HxOUBovV_D335SFGOiPeogYGobzGhnqFdQ3wTAdy_aLFXiN8SYpCwIx_GugrI1x2JzCZ6INV_VVvp6gzYIr6nUNooQt0EwnlrsNlaFHIemFMmNoOHSTKvgXI49ZCVpBSZ3fQEtQPMlq2RB099VCLDTofBTOJvlYo4VPA5uxbs5pHa3ULGg","header":{"alg":"RSA-OAEP"},"iv":"YWtQIqXd8VYpjBGZ","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","tag":"94UMzAd_b8yQJq6e3R2a-g"}
}
```
source: [examples/jwe_parse_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_parse_example_test.go)
<!-- END INCLUDE -->

## Parse a JWE message stored in a file

To parse a JWE stored in a file, use [`jwe.ParseFS()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwe#ParseFS). [`jwe.ParseFS()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwe#ParseFS) accepts the same options as [`jwe.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwe#Parse).

<!-- INCLUDE(examples/jwe_parsefs_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"
  "path/filepath"

  "github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_ParseFS() {
  // Same canonical sample JWE as Example_jwe_parse, written out to a
  // file and parsed back via jwe.ParseFS. alg=RSA-OAEP, enc=A256GCM.
  const src = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.QoQNICnJzzytxWd9FOy6PgP2Qyh6HAPXWBXSdaWCX7upX_mzXBdR2r6zJgb-8HgAMJ9dXJvTaaoNq6J5JOOZMUprnPy08rwACkKK_lR363C380_LHlYmqDQGPoqUt97m2ZDUgfGDKv7ilw6SAQpGZ7e3eOY4g_qINmJ8HxOUBovV_D335SFGOiPeogYGobzGhnqFdQ3wTAdy_aLFXiN8SYpCwIx_GugrI1x2JzCZ6INV_VVvp6gzYIr6nUNooQt0EwnlrsNlaFHIemFMmNoOHSTKvgXI49ZCVpBSZ3fQEtQPMlq2RB099VCLDTofBTOJvlYo4VPA5uxbs5pHa3ULGg.YWtQIqXd8VYpjBGZ.KmJpIgDVk-c0Ei4.94UMzAd_b8yQJq6e3R2a-g`

  f, err := os.CreateTemp(``, `jwe_parsefs_example-*.jwe`)
  if err != nil {
    fmt.Printf("failed to create temporary file: %s\n", err)
    return
  }
  defer os.Remove(f.Name())

  f.Write([]byte(src))
  f.Close()

  msg, err := jwe.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()))
  if err != nil {
    fmt.Printf("failed to parse JWE message from file %q: %s\n", f.Name(), err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(msg)
  // OUTPUT:
  // {"ciphertext":"KmJpIgDVk-c0Ei4","encrypted_key":"QoQNICnJzzytxWd9FOy6PgP2Qyh6HAPXWBXSdaWCX7upX_mzXBdR2r6zJgb-8HgAMJ9dXJvTaaoNq6J5JOOZMUprnPy08rwACkKK_lR363C380_LHlYmqDQGPoqUt97m2ZDUgfGDKv7ilw6SAQpGZ7e3eOY4g_qINmJ8HxOUBovV_D335SFGOiPeogYGobzGhnqFdQ3wTAdy_aLFXiN8SYpCwIx_GugrI1x2JzCZ6INV_VVvp6gzYIr6nUNooQt0EwnlrsNlaFHIemFMmNoOHSTKvgXI49ZCVpBSZ3fQEtQPMlq2RB099VCLDTofBTOJvlYo4VPA5uxbs5pHa3ULGg","header":{"alg":"RSA-OAEP"},"iv":"YWtQIqXd8VYpjBGZ","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","tag":"94UMzAd_b8yQJq6e3R2a-g"}
}
```
source: [examples/jwe_parsefs_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_parsefs_example_test.go)
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

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwe_encrypt() {
  rawprivkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to create raw private key: %s\n", err)
    return
  }
  privkey, err := jwk.Import[jwk.Key](rawprivkey)
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
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP_256(), pubkey))
  if err != nil {
    fmt.Printf("failed to encrypt payload: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP_256(), privkey))
  if err != nil {
    fmt.Printf("failed to decrypt payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Lorem ipsum
}
```
source: [examples/jwe_encrypt_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_encrypt_example_test.go)
<!-- END INCLUDE -->

## Generating a JWE message in JSON serialization format

Generally the only time you need to use a JSON serialization format is when you have to generate multiple recipients (encrypted keys) for a given payload using multiple encryption algorithms and keys.

When this need arises, use the [`jwe.Encrypt()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws#Encrypt) function with the `jwe.WithJSON()` option and multiple `jwe.WithKey()` options:

<!-- INCLUDE(examples/jwe_encrypt_json_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwe_encrypt_json() {
  rawprivkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to create raw private key: %s\n", err)
    return
  }
  privkey, err := jwk.Import[jwk.Key](rawprivkey)
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
  encrypted, err := jwe.Encrypt(
    []byte(payload),
    jwe.WithJSON(),                      // Toggle JSON serialization. Because there's only one key (recipient), this will produce Flattened JSON serialization
    jwe.WithKey(jwa.RSA_OAEP_256(), pubkey), // Public key for encryption
  )
  if err != nil {
    fmt.Printf("failed to encrypt payload: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP_256(), privkey))
  if err != nil {
    fmt.Printf("failed to decrypt payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Lorem ipsum
}

func Example_jwe_encrypt_json_multi() {
  var privkeys []jwk.Key
  var pubkeys []jwk.Key

  for i := 0; i < 3; i++ {
    rawprivkey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
      fmt.Printf("failed to create raw private key: %s\n", err)
      return
    }
    privkey, err := jwk.Import[jwk.Key](rawprivkey)
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
    options = append(options, jwe.WithKey(jwa.RSA_OAEP_256(), key))
  }

  const payload = `Lorem ipsum`
  encrypted, err := jwe.Encrypt([]byte(payload), options...)
  if err != nil {
    fmt.Printf("failed to encrypt payload: %s\n", err)
    return
  }

  for _, key := range privkeys {
    decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP_256(), key))
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
source: [examples/jwe_encrypt_json_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_encrypt_json_example_test.go)
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

  "encoding/json"
  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_encrypt_with_headers() {
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to create private key: %s\n", err)
    return
  }
  const payload = "Lorem ipsum"

  hdrs := jwe.NewHeaders()
  hdrs.Set(`x-example`, true)
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP_256(), privkey.PublicKey, jwe.WithPerRecipientHeaders(hdrs)))
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
  // {"alg":"RSA-OAEP-256","enc":"A256GCM","x-example":true}
}
```
source: [examples/jwe_encrypt_with_headers_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_encrypt_with_headers_example_test.go)
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

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_verify_with_key() {
  const payload = "Lorem ipsum"
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP_256(), jwkRSAPublicKey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP_256(), jwkRSAPrivateKey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Lorem ipsum
}
```
source: [examples/jwe_decrypt_with_key_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_decrypt_with_key_example_test.go)
<!-- END INCLUDE -->

## Decrypting using a JWKS

To decrypt a payload using JWKS, the JWE's `kid` header selects a key from the set; the key's `alg` field (when present) is used for the decrypt-time dispatch. When the JWK lacks `alg`, the recipient's `alg` header (per-recipient first, then protected) is used as a fallback — `jwe.Decrypt` re-checks the chosen `alg` against the integrity-protected protected header before any cryptographic call (RFC 7516 §7.2.1).

For more discussion on why `alg` cannot be inferred from the key alone, see "[Why don't you automatically infer the algorithm for `jws.Verify`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)" — the same reasoning applies to `jwe.Decrypt()`.

`kid` IS required by default. The example below uses `jwe.WithRequireKid(false)` to opt out and try every key in the set; this is slower and looser, intended for legacy peers that don't emit `kid`.

For more discussion on why/how `alg`/`kid` values work, please read the [relevant section in the JWT documentation](01-jwt.md#parse-and-verify-a-jwt-with-a-key-set-matching-kid).

<!-- INCLUDE(examples/jwe_decrypt_with_keyset_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwe_verify_with_jwk_set() {
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to create private key: %s\n", err)
    return
  }
  const payload = "Lorem ipsum"
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP_256(), privkey.PublicKey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }

  // Create a JWK Set
  set := jwk.NewSet()
  // Add some bogus keys
  k1, _ := jwk.Import[jwk.Key]([]byte("abracadabra"))
  set.AddKey(k1)
  k2, _ := jwk.Import[jwk.Key]([]byte("opensesame"))
  set.AddKey(k2)
  // Add the real thing
  k3, _ := jwk.Import[jwk.Key](privkey)
  k3.Set(jwk.AlgorithmKey, jwa.RSA_OAEP_256())
  set.AddKey(k3)

  // Up to this point, you probably will replace with a simple
  // jwkfetch.NewClient().Fetch() or similar to obtain the JWKS

  if _, err := jwe.Decrypt(encrypted, jwe.WithKeySet(set, jwe.WithRequireKid(false))); err != nil {
    fmt.Printf("Failed to decrypt using jwk.Set: %s", err)
  }

  // OUTPUT:
}
```
source: [examples/jwe_decrypt_with_keyset_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_decrypt_with_keyset_example_test.go)
<!-- END INCLUDE -->

# HPKE (Hybrid Public Key Encryption)

jwx v4 supports HPKE-based key encryption as defined in [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/). HPKE replaces the traditional two-step process (generate a random CEK, then wrap it) with a single KEM+KDF+AEAD operation.

The following ciphersuites are built in:

| Algorithm | KEM | KDF | AEAD |
|:----------|:----|:----|:-----|
| `HPKE-0-KE` | DHKEM(P-256) | HKDF-SHA256 | AES-128-GCM |
| `HPKE-1-KE` | DHKEM(P-384) | HKDF-SHA384 | AES-256-GCM |
| `HPKE-2-KE` | DHKEM(P-521) | HKDF-SHA512 | AES-256-GCM |
| `HPKE-3-KE` | DHKEM(X25519) | HKDF-SHA256 | AES-128-GCM |
| `HPKE-4-KE` | DHKEM(X25519) | HKDF-SHA256 | ChaCha20Poly1305 |
| `HPKE-7-KE` | DHKEM(P-256) | HKDF-SHA256 | AES-256-GCM |

X448 variants (HPKE-5-KE, HPKE-6-KE) are not built in because Go's standard library does not include X448. They can be provided by a companion module — see [Extension Modules](10-extensions.md#x448).

Encrypt and decrypt with HPKE using the same `jwe.Encrypt` / `jwe.Decrypt` API as any other algorithm. Pass an `*ecdh.PublicKey` or `*ecdsa.PublicKey` for encryption, and the corresponding private key for decryption. `jwk.Key` values are also accepted.

<!-- INCLUDE(examples/jwe_hpke_example_test.go) -->
```go
package examples_test

import (
  "crypto/ecdh"
  "crypto/rand"
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_hpke() {
  // HPKE (Hybrid Public Key Encryption) combines KEM, KDF, and AEAD
  // in a single operation. jwx v4 supports six built-in ciphersuites
  // based on draft-ietf-jose-hpke-encrypt.
  //
  // HPKE-0-KE through HPKE-4-KE and HPKE-7-KE are available via
  // jwa.HPKE_0_KE(), jwa.HPKE_1_KE(), etc.
  //
  // The API is identical to any other JWE key encryption algorithm.
  // Pass an *ecdh.PublicKey for encryption, *ecdh.PrivateKey for
  // decryption. *ecdsa.PublicKey / *ecdsa.PrivateKey also work for
  // the NIST curve variants.

  const payload = "Hello, HPKE!"

  // HPKE-0-KE uses DHKEM(P-256), HKDF-SHA256, AES-128-GCM
  priv, err := ecdh.P256().GenerateKey(rand.Reader)
  if err != nil {
    fmt.Printf("failed to generate key: %s\n", err)
    return
  }

  encrypted, err := jwe.Encrypt([]byte(payload),
    jwe.WithKey(jwa.HPKE_0_KE(), priv.PublicKey()),
    jwe.WithContentEncryption(jwa.A256GCM()),
  )
  if err != nil {
    fmt.Printf("failed to encrypt: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted,
    jwe.WithKey(jwa.HPKE_0_KE(), priv),
  )
  if err != nil {
    fmt.Printf("failed to decrypt: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Hello, HPKE!
}
```
source: [examples/jwe_hpke_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_hpke_example_test.go)
<!-- END INCLUDE -->

For X25519-based HPKE (HPKE-3-KE, HPKE-4-KE):

<!-- INCLUDE(examples/jwe_hpke_x25519_example_test.go) -->
```go
package examples_test

import (
  "crypto/ecdh"
  "crypto/rand"
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_hpke_x25519() {
  // HPKE-3-KE and HPKE-4-KE use DHKEM(X25519).
  // HPKE-3-KE pairs it with HKDF-SHA256 and AES-128-GCM.
  // HPKE-4-KE pairs it with HKDF-SHA256 and ChaCha20Poly1305.

  const payload = "Hello, X25519 HPKE!"

  priv, err := ecdh.X25519().GenerateKey(rand.Reader)
  if err != nil {
    fmt.Printf("failed to generate key: %s\n", err)
    return
  }

  encrypted, err := jwe.Encrypt([]byte(payload),
    jwe.WithKey(jwa.HPKE_4_KE(), priv.PublicKey()),
    jwe.WithContentEncryption(jwa.A256GCM()),
  )
  if err != nil {
    fmt.Printf("failed to encrypt: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted,
    jwe.WithKey(jwa.HPKE_4_KE(), priv),
  )
  if err != nil {
    fmt.Printf("failed to decrypt: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Hello, X25519 HPKE!
}
```
source: [examples/jwe_hpke_x25519_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_hpke_x25519_example_test.go)
<!-- END INCLUDE -->

HPKE stores the encapsulated key in the `"ek"` JWE header field. When parsing an HPKE message, this field is accessible via `headers.EncapsulatedKey()`.

# ECDH-ES with X25519

X25519 keys work with the standard ECDH-ES family of algorithms (`ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`) the same way NIST curves do. X25519 keys are represented in JWK as OKP keys with `crv=X25519`.

<!-- INCLUDE(examples/jwe_ecdh_es_x25519_example_test.go) -->
```go
package examples_test

import (
  "crypto/ecdh"
  "crypto/rand"
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwe_ecdh_es_x25519() {
  // X25519 keys work with the standard ECDH-ES family of algorithms
  // (ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW) the
  // same way NIST curves do.
  //
  // Use *ecdh.PublicKey / *ecdh.PrivateKey from crypto/ecdh with the
  // X25519 curve. JWK keys are also accepted.

  const payload = "Hello, X25519 ECDH-ES!"

  priv, err := ecdh.X25519().GenerateKey(rand.Reader)
  if err != nil {
    fmt.Printf("failed to generate key: %s\n", err)
    return
  }

  // Encrypt with ECDH-ES+A256KW
  encrypted, err := jwe.Encrypt([]byte(payload),
    jwe.WithKey(jwa.ECDH_ES_A256KW(), priv.PublicKey()),
    jwe.WithContentEncryption(jwa.A256GCM()),
  )
  if err != nil {
    fmt.Printf("failed to encrypt: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted,
    jwe.WithKey(jwa.ECDH_ES_A256KW(), priv),
  )
  if err != nil {
    fmt.Printf("failed to decrypt: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)

  // X25519 keys are represented as OKP keys with crv=X25519 in JWK
  privJWK, err := jwk.Import[jwk.Key](priv)
  if err != nil {
    fmt.Printf("failed to import key: %s\n", err)
    return
  }
  fmt.Printf("kty=%s\n", privJWK.KeyType())

  // OUTPUT:
  // Hello, X25519 ECDH-ES!
  // kty=OKP
}
```
source: [examples/jwe_ecdh_es_x25519_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_ecdh_es_x25519_example_test.go)
<!-- END INCLUDE -->

For X448, import [`github.com/jwx-go/x448/v4`](https://github.com/jwx-go/x448) — see [Extension Modules](10-extensions.md#x448).

# Filtering JWE headers

**Important**: Filtering operates on JWE headers only, not the JWE message or encrypted payload itself. When working with JWE messages, you may need to filter or manipulate the headers for various purposes while leaving the encrypted content intact.

Header filtering is particularly useful for:

- Removing sensitive information from headers before logging or transmission
- Extract only specific header fields for processing  
- Separate standard JWE headers from custom application-specific headers
- Create environment-specific header configurations

The filtering operates on parsed JWE messages and their headers, allowing you to create new header objects with only the fields you need.

## Basic header filtering

You can filter JWE headers using the [`jwe.HeaderNameFilter`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwe#HeaderNameFilter):

<!-- INCLUDE(examples/jwe_filter_basic_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/jwx-go/jwxfilter/v4/jwefilter"
  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
)

// Example_jwe_filter_basic demonstrates basic JWE header filtering via the
// jwefilter companion package. Filters were extracted out of jwx core in
// v4 (github.com/jwx-go/jwxfilter/v4/jwefilter).
func Example_jwe_filter_basic() {
  // Construct JWE protected headers with both RFC 7516 standard fields
  // and application-specific custom fields.
  protectedHeaders := jwe.NewHeaders()
  protectedHeaders.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256())
  protectedHeaders.Set(jwe.ContentEncryptionKey, jwa.A256GCM())
  protectedHeaders.Set(jwe.ContentTypeKey, "application/json")
  protectedHeaders.Set(jwe.KeyIDKey, "example-key-1")
  protectedHeaders.Set("custom-header", "custom-value")
  protectedHeaders.Set("app-id", "my-app")
  protectedHeaders.Set("version", "1.0")

  headers := protectedHeaders

  // jwefilter.ByName builds a filter over jwe.Headers for the given
  // field names. Filter returns a fresh copy containing only the
  // matching fields.
  customFilter := jwefilter.ByName("custom-header", "app-id", jwe.KeyIDKey)

  filteredHeaders, err := customFilter.Filter(headers)
  if err != nil {
    fmt.Printf("ByName.Filter failed: %s\n", err)
    return
  }
  if len(filteredHeaders.Keys()) == 0 {
    fmt.Printf("No filtered headers found\n")
    return
  }

  // jwefilter.Standard() is the preset for the 18 RFC 7516 standard
  // headers. Use Filter to keep only them.
  stdFilter := jwefilter.Standard()

  standardHeaders, err := stdFilter.Filter(headers)
  if err != nil {
    fmt.Printf("Standard.Filter failed: %s\n", err)
    return
  }
  if len(standardHeaders.Keys()) == 0 {
    fmt.Printf("No standard headers found\n")
    return
  }

  // Reject keeps everything except the named fields — useful for
  // scrubbing specific custom fields before logging or forwarding.
  rejectFilter := jwefilter.ByName("version", "custom-header")

  rejectedHeaders, err := rejectFilter.Reject(headers)
  if err != nil {
    fmt.Printf("ByName.Reject failed: %s\n", err)
    return
  }
  if len(rejectedHeaders.Keys()) == 0 {
    fmt.Printf("No rejected headers found\n")
    return
  }

  // Reject on the standard filter keeps only custom fields.
  customOnlyHeaders, err := stdFilter.Reject(headers)
  if err != nil {
    fmt.Printf("Standard.Reject failed: %s\n", err)
    return
  }
  if len(customOnlyHeaders.Keys()) == 0 {
    fmt.Printf("No custom only headers found\n")
    return
  }

  // OUTPUT:
}
```
source: [examples/jwe_filter_basic_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_filter_basic_example_test.go)
<!-- END INCLUDE -->

## Advanced header filtering

For more complex filtering scenarios, including multi-recipient JWE messages:

<!-- INCLUDE(examples/jwe_filter_advanced_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/jwx-go/jwxfilter/v4/jwefilter"
  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
)

// Example_jwe_filter_advanced demonstrates advanced JWE HeaderFilter functionality
// with security filtering, service integration scenarios, and header manipulation.
func Example_jwe_filter_advanced() {
  // Create JWE headers with comprehensive metadata including security and service information
  protectedHeaders := jwe.NewHeaders()
  protectedHeaders.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256())
  protectedHeaders.Set(jwe.ContentEncryptionKey, jwa.A256GCM())
  protectedHeaders.Set(jwe.ContentTypeKey, "application/json")
  protectedHeaders.Set(jwe.KeyIDKey, "service-key-001")

  // Security headers
  protectedHeaders.Set("security_level", "high")
  protectedHeaders.Set("access_control", "restricted")
  protectedHeaders.Set("encryption_version", "v2.1")

  // Service integration headers
  protectedHeaders.Set("service_name", "user-service")
  protectedHeaders.Set("api_version", "v1.2.3")
  protectedHeaders.Set("request_id", "req-789abc")
  protectedHeaders.Set("correlation_id", "corr-456def")

  // Operational headers
  protectedHeaders.Set("environment", "production")
  protectedHeaders.Set("region", "us-east-1")
  protectedHeaders.Set("trace_id", "trace-123xyz")

  // Use the headers directly for filtering examples
  headers := protectedHeaders

  // Advanced Example 1: Service Integration - Filter service-related headers
  serviceFilter := jwefilter.ByName("service_name", "api_version", "request_id", "correlation_id", jwe.KeyIDKey)
  serviceHeaders, err := serviceFilter.Filter(headers)
  if err != nil {
    fmt.Printf("Failed to filter service headers: %s\n", err)
    return
  }

  // Advanced Example 2: Security Headers - Filter security-related metadata
  securityFilter := jwefilter.ByName("security_level", "access_control", "encryption_version", jwe.AlgorithmKey, jwe.ContentEncryptionKey)
  securityHeaders, err := securityFilter.Filter(headers)
  if err != nil {
    fmt.Printf("Failed to filter security headers: %s\n", err)
    return
  }

  // Advanced Example 3: Operational Headers - Filter operational metadata
  operationalFilter := jwefilter.ByName("environment", "region", "trace_id")
  operationalHeaders, err := operationalFilter.Filter(headers)
  if err != nil {
    fmt.Printf("Failed to filter operational headers: %s\n", err)
    return
  }
  // Use operationalHeaders variable by checking its length
  if len(operationalHeaders.Keys()) == 0 {
    fmt.Printf("No operational headers found\n")
    return
  }

  // Advanced Example 4: Public Headers - Remove sensitive headers for public APIs
  sensitiveFilter := jwefilter.ByName("security_level", "access_control", "encryption_version", "trace_id")
  publicHeaders, err := sensitiveFilter.Reject(headers)
  if err != nil {
    fmt.Printf("Failed to create public headers: %s\n", err)
    return
  }
  // Use publicHeaders variable by checking its length
  if len(publicHeaders.Keys()) == 0 {
    fmt.Printf("No public headers found\n")
    return
  }

  // Advanced Example 5: Minimal Headers - Keep only essential headers for bandwidth optimization
  essentialFilter := jwefilter.ByName(jwe.AlgorithmKey, jwe.ContentEncryptionKey, jwe.KeyIDKey)
  minimalHeaders, err := essentialFilter.Filter(headers)
  if err != nil {
    fmt.Printf("Failed to filter minimal headers: %s\n", err)
    return
  }
  // Use minimalHeaders variable by checking its length
  if len(minimalHeaders.Keys()) == 0 {
    fmt.Printf("No minimal headers found\n")
    return
  }

  // Advanced Example 6: Custom Validation - Filter headers based on security requirements
  isValidSecurityLevel := validateJWESecurityHeaders(securityHeaders)
  if !isValidSecurityLevel {
    fmt.Printf("Security validation failed\n")
    return
  }

  isValidServiceConfig := validateJWEServiceHeaders(serviceHeaders)
  if !isValidServiceConfig {
    fmt.Printf("Service configuration validation failed\n")
    return
  }

  // Advanced Example 7: Header transformation for different environments
  prodHeaders := createJWEEnvironmentHeaders(headers, "production")
  if len(prodHeaders.Keys()) == 0 {
    fmt.Printf("Failed to create production headers\n")
    return
  }

  testHeaders := createJWEEnvironmentHeaders(headers, "testing")
  if len(testHeaders.Keys()) == 0 {
    fmt.Printf("Failed to create testing headers\n")
    return
  }

  // OUTPUT:
}

// validateJWESecurityHeaders checks if security headers meet requirements
func validateJWESecurityHeaders(headers jwe.Headers) bool {
  // Check security level
  securityLevelV, ok := headers.Field("security_level")
  if !ok {
    return false
  }
  securityLevel, ok := securityLevelV.(string)
  if !ok || securityLevel != "high" {
    return false
  }

  // Check access control
  accessControlV, ok := headers.Field("access_control")
  if !ok {
    return false
  }
  accessControl, ok := accessControlV.(string)
  if !ok || accessControl != "restricted" {
    return false
  }

  // Check encryption algorithm
  if algValue, ok := headers.Algorithm(); !ok || algValue != jwa.RSA_OAEP_256() {
    return false
  }

  return true
}

// validateJWEServiceHeaders checks if service headers are properly configured
func validateJWEServiceHeaders(headers jwe.Headers) bool {
  requiredHeaders := []string{"service_name", "api_version", "request_id", "correlation_id"}

  for _, header := range requiredHeaders {
    if !headers.Has(header) {
      return false
    }
  }

  // Validate API version format
  apiVersionV, ok := headers.Field("api_version")
  if !ok {
    return false
  }
  apiVersion, ok := apiVersionV.(string)
  if !ok || len(apiVersion) < 5 {
    return false
  }

  return true
}

// createJWEEnvironmentHeaders creates environment-specific header configurations
func createJWEEnvironmentHeaders(originalHeaders jwe.Headers, environment string) jwe.Headers {
  switch environment {
  case "production":
    // Production: Include security and service headers, exclude debug info
    prodFilter := jwefilter.ByName(
      jwe.AlgorithmKey, jwe.ContentEncryptionKey, jwe.ContentTypeKey, jwe.KeyIDKey,
      "security_level", "access_control", "service_name", "api_version", "environment", "region",
    )
    filtered, err := prodFilter.Filter(originalHeaders)
    if err != nil {
      fmt.Printf("Failed to create production headers: %s\n", err)
      return jwe.NewHeaders()
    }
    return filtered

  case "testing":
    // Testing: Include debug headers, exclude some security headers
    testFilter := jwefilter.ByName(
      jwe.AlgorithmKey, jwe.ContentEncryptionKey, jwe.ContentTypeKey, jwe.KeyIDKey,
      "service_name", "api_version", "request_id", "correlation_id", "trace_id", "environment",
    )
    filtered, err := testFilter.Filter(originalHeaders)
    if err != nil {
      fmt.Printf("Failed to create testing headers: %s\n", err)
      return jwe.NewHeaders()
    }
    return filtered

  default:
    // Default: Use standard headers only
    stdFilter := jwefilter.Standard()
    filtered, err := stdFilter.Filter(originalHeaders)
    if err != nil {
      fmt.Printf("Failed to create default headers: %s\n", err)
      return jwe.NewHeaders()
    }
    return filtered
  }
}
```
source: [examples/jwe_filter_advanced_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_filter_advanced_example_test.go)
<!-- END INCLUDE -->
