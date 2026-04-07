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
source: [examples/jwe_parse_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jwe_parse_example_test.go)
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
  const src = `eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.KrFTaMKVY_iUKYYk905QjbUf_fpBXvXCzIAfbPoPMGViDzxtgz5qnch8waV7wraVDfzpW7JfPOw6Nz_-XRwN3Vbud48bRYFw92GkC0M6kpKFpl_xgZxGN47ggNk9hzgqd7mFCuyufeYdn5c2fPoRZAV4UxvakLozEYcQo-eZaFmoYS4pyoC-IKKRikobW8n__LksMzXc_Vps1axn5kdpxsKQ4k1oayvUrgWX2PMxKn_TcLEKHtCN7qRlJ5hkKbZAXAdd34zGWcFV5gc1tcLs6HFhnebo8GUgItTYWBKSKzF6MyLJNRSUPFVq9q-Jxi1juXIlDrv_7rHVsdokQmBfvA.bK7z7Z3gEzFDgDQvNen0Ww.2hngnAVrmucUpJKLgIzYcg.CHs3ZP7JtG430Dl9YAKLMAl`

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
  // {"ciphertext":"2hngnAVrmucUpJKLgIzYcg","encrypted_key":"KrFTaMKVY_iUKYYk905QjbUf_fpBXvXCzIAfbPoPMGViDzxtgz5qnch8waV7wraVDfzpW7JfPOw6Nz_-XRwN3Vbud48bRYFw92GkC0M6kpKFpl_xgZxGN47ggNk9hzgqd7mFCuyufeYdn5c2fPoRZAV4UxvakLozEYcQo-eZaFmoYS4pyoC-IKKRikobW8n__LksMzXc_Vps1axn5kdpxsKQ4k1oayvUrgWX2PMxKn_TcLEKHtCN7qRlJ5hkKbZAXAdd34zGWcFV5gc1tcLs6HFhnebo8GUgItTYWBKSKzF6MyLJNRSUPFVq9q-Jxi1juXIlDrv_7rHVsdokQmBfvA","header":{"alg":"RSA1_5"},"iv":"bK7z7Z3gEzFDgDQvNen0Ww","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","tag":"CHs3ZP7JtG430Dl9YAKLMAk"}
}
```
source: [examples/jwe_parsefs_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jwe_parsefs_example_test.go)
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
  privkey, err := jwk.Import(rawprivkey)
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
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP(), pubkey))
  if err != nil {
    fmt.Printf("failed to encrypt payload: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP(), privkey))
  if err != nil {
    fmt.Printf("failed to decrypt payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Lorem ipsum
}
```
source: [examples/jwe_encrypt_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jwe_encrypt_example_test.go)
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
  privkey, err := jwk.Import(rawprivkey)
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
    jwe.WithKey(jwa.RSA_OAEP(), pubkey), // Public key for encryption
  )
  if err != nil {
    fmt.Printf("failed to encrypt payload: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP(), privkey))
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
    privkey, err := jwk.Import(rawprivkey)
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
    options = append(options, jwe.WithKey(jwa.RSA_OAEP(), key))
  }

  const payload = `Lorem ipsum`
  encrypted, err := jwe.Encrypt([]byte(payload), options...)
  if err != nil {
    fmt.Printf("failed to encrypt payload: %s\n", err)
    return
  }

  for _, key := range privkeys {
    decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP(), key))
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
source: [examples/jwe_encrypt_json_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jwe_encrypt_json_example_test.go)
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

  "github.com/lestrrat-go/jwx/v4/internal/json"
  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_sign_with_headers() {
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to create private key: %s\n", err)
    return
  }
  const payload = "Lorem ipsum"

  hdrs := jwe.NewHeaders()
  hdrs.Set(`x-example`, true)
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP(), privkey.PublicKey, jwe.WithPerRecipientHeaders(hdrs)))
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
source: [examples/jwe_encrypt_with_headers_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jwe_encrypt_with_headers_example_test.go)
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
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP(), jwkRSAPublicKey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP(), jwkRSAPrivateKey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }
  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Lorem ipsum
}
```
source: [examples/jwe_decrypt_with_key_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jwe_decrypt_with_key_example_test.go)
<!-- END INCLUDE -->

## Decrypting using a JWKS

To decrypt a payload using JWKS, by default you will need your payload and JWKS to have matching `alg` field.

The `alg` field's requirement is the same for using a single key. See "[Why don't you automatically infer the algorithm for `jws.Verify`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsverify-)", it's the same for `jwe.Decrypt()`.

Note that unlike in JWT, the `kid` is not required by default, although you _can_ make it so
by passing `jwe.WithRequireKid(true)`.

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
  encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP(), privkey.PublicKey))
  if err != nil {
    fmt.Printf("failed to sign payload: %s\n", err)
    return
  }

  // Create a JWK Set
  set := jwk.NewSet()
  // Add some bogus keys
  k1, _ := jwk.Import([]byte("abracadabra"))
  set.AddKey(k1)
  k2, _ := jwk.Import([]byte("opensesame"))
  set.AddKey(k2)
  // Add the real thing
  k3, _ := jwk.Import(privkey)
  k3.Set(jwk.AlgorithmKey, jwa.RSA_OAEP())
  set.AddKey(k3)

  // Up to this point, you probably will replace with a simple jwk.Fetch()

  if _, err := jwe.Decrypt(encrypted, jwe.WithKeySet(set, jwe.WithRequireKid(false))); err != nil {
    fmt.Printf("Failed to decrypt using jwk.Set: %s", err)
  }

  // OUTPUT:
}
```
source: [examples/jwe_decrypt_with_keyset_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jwe_decrypt_with_keyset_example_test.go)
<!-- END INCLUDE -->

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

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
)

// Example_jwe_filter_basic demonstrates basic JWE HeaderFilter functionality
// with HeaderNameFilter.Filter(), StandardHeadersFilter(), and HeaderNameFilter.Reject() methods.
func Example_jwe_filter_basic() {
  // Create JWE headers with custom headers for filtering demonstration
  protectedHeaders := jwe.NewHeaders()
  protectedHeaders.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256())
  protectedHeaders.Set(jwe.ContentEncryptionKey, jwa.A256GCM)
  protectedHeaders.Set(jwe.ContentTypeKey, "application/json")
  protectedHeaders.Set(jwe.KeyIDKey, "example-key-1")
  protectedHeaders.Set("custom-header", "custom-value")
  protectedHeaders.Set("app-id", "my-app")
  protectedHeaders.Set("version", "1.0")

  // Use the headers directly for filtering examples
  headers := protectedHeaders

  // Example 1: HeaderNameFilter.Filter() - Include only specific headers
  customFilter := jwe.NewHeaderNameFilter("custom-header", "app-id", jwe.KeyIDKey)

  filteredHeaders, err := customFilter.Filter(headers)
  if err != nil {
    fmt.Printf("HeaderNameFilter.Filter failed: %s\n", err)
    return
  }
  // Use filteredHeaders variable by checking its length
  if len(filteredHeaders.Keys()) == 0 {
    fmt.Printf("No filtered headers found\n")
    return
  }

  // Example 2: StandardHeadersFilter() - Include only standard JWE headers
  stdFilter := jwe.StandardHeadersFilter()

  standardHeaders, err := stdFilter.Filter(headers)
  if err != nil {
    fmt.Printf("StandardHeadersFilter.Filter failed: %s\n", err)
    return
  }
  // Use standardHeaders variable by checking its length
  if len(standardHeaders.Keys()) == 0 {
    fmt.Printf("No standard headers found\n")
    return
  }

  // Example 3: HeaderNameFilter.Reject() - Exclude specific headers
  rejectFilter := jwe.NewHeaderNameFilter("version", "custom-header")

  rejectedHeaders, err := rejectFilter.Reject(headers)
  if err != nil {
    fmt.Printf("HeaderNameFilter.Reject failed: %s\n", err)
    return
  }
  // Use rejectedHeaders variable by checking its length
  if len(rejectedHeaders.Keys()) == 0 {
    fmt.Printf("No rejected headers found\n")
    return
  }

  // Example 4: StandardHeadersFilter().Reject() - Exclude standard headers, keep custom
  customOnlyHeaders, err := stdFilter.Reject(headers)
  if err != nil {
    fmt.Printf("StandardHeadersFilter.Reject failed: %s\n", err)
    return
  }
  // Use customOnlyHeaders variable by checking its length
  if len(customOnlyHeaders.Keys()) == 0 {
    fmt.Printf("No custom only headers found\n")
    return
  }

  // OUTPUT:
}
```
source: [examples/jwe_filter_basic_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jwe_filter_basic_example_test.go)
<!-- END INCLUDE -->

## Advanced header filtering

For more complex filtering scenarios, including multi-recipient JWE messages:

<!-- INCLUDE(examples/jwe_filter_advanced_example_test.go) -->
```go
package examples_test

import (
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
)

// Example_jwe_filter_advanced demonstrates advanced JWE HeaderFilter functionality
// with security filtering, service integration scenarios, and header manipulation.
func Example_jwe_filter_advanced() {
  // Create JWE headers with comprehensive metadata including security and service information
  protectedHeaders := jwe.NewHeaders()
  protectedHeaders.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256())
  protectedHeaders.Set(jwe.ContentEncryptionKey, jwa.A256GCM)
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
  serviceFilter := jwe.NewHeaderNameFilter("service_name", "api_version", "request_id", "correlation_id", jwe.KeyIDKey)
  serviceHeaders, err := serviceFilter.Filter(headers)
  if err != nil {
    fmt.Printf("Failed to filter service headers: %s\n", err)
    return
  }

  // Advanced Example 2: Security Headers - Filter security-related metadata
  securityFilter := jwe.NewHeaderNameFilter("security_level", "access_control", "encryption_version", jwe.AlgorithmKey, jwe.ContentEncryptionKey)
  securityHeaders, err := securityFilter.Filter(headers)
  if err != nil {
    fmt.Printf("Failed to filter security headers: %s\n", err)
    return
  }

  // Advanced Example 3: Operational Headers - Filter operational metadata
  operationalFilter := jwe.NewHeaderNameFilter("environment", "region", "trace_id")
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
  sensitiveFilter := jwe.NewHeaderNameFilter("security_level", "access_control", "encryption_version", "trace_id")
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
  essentialFilter := jwe.NewHeaderNameFilter(jwe.AlgorithmKey, jwe.ContentEncryptionKey, jwe.KeyIDKey)
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
  var securityLevel string
  if err := headers.Get("security_level", &securityLevel); err != nil || securityLevel != "high" {
    return false
  }

  // Check access control
  var accessControl string
  if err := headers.Get("access_control", &accessControl); err != nil || accessControl != "restricted" {
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
  var apiVersion string
  if err := headers.Get("api_version", &apiVersion); err != nil || len(apiVersion) < 5 {
    return false
  }

  return true
}

// createJWEEnvironmentHeaders creates environment-specific header configurations
func createJWEEnvironmentHeaders(originalHeaders jwe.Headers, environment string) jwe.Headers {
  switch environment {
  case "production":
    // Production: Include security and service headers, exclude debug info
    prodFilter := jwe.NewHeaderNameFilter(
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
    testFilter := jwe.NewHeaderNameFilter(
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
    stdFilter := jwe.StandardHeadersFilter()
    filtered, err := stdFilter.Filter(originalHeaders)
    if err != nil {
      fmt.Printf("Failed to create default headers: %s\n", err)
      return jwe.NewHeaders()
    }
    return filtered
  }
}
```
source: [examples/jwe_filter_advanced_example_test.go](https://github.com/lestrrat-go/jwx/blob/v3/examples/jwe_filter_advanced_example_test.go)
<!-- END INCLUDE -->
