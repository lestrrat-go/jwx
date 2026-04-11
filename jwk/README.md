# JWK [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/v4/jwk.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk)

Package jwk implements JWK as described in [RFC 7517](https://tools.ietf.org/html/rfc7517).

## Supported key types:

| kty | Curve | Go Key Type |
|:----|:------|:------------|
| RSA | N/A | `rsa.PrivateKey` / `rsa.PublicKey` (*) |
| EC  | P-256, P-384, P-521 | `ecdsa.PrivateKey` / `ecdsa.PublicKey` (*) |
| oct | N/A | `[]byte` |
| OKP | Ed25519, X25519, X448 | `ed25519.PrivateKey` / `ed25519.PublicKey`, `x25519.PrivateKey` / `x25519.PublicKey` (*) |
| AKP | ML-KEM-768, ML-KEM-1024 | `mlkem.EncapsulationKey` / `mlkem.DecapsulationKey` (*) |

(*) Either value or pointers accepted (e.g. `rsa.PrivateKey` or `*rsa.PrivateKey`)

Additional key types available via [extension modules](../docs/10-extensions.md): secp256k1 (ES256K), Ed448, ML-DSA.

## Parse and use a JWK key

<!-- INCLUDE(examples/jwk_example_test.go) -->
```go
package examples_test

import (
  "context"
  "fmt"
  "log"

  "encoding/json"
  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwk_usage() {
  // Use jwk.Cache if you intend to keep reuse the JWKS over and over
  set, err := jwk.Fetch(context.Background(), "https://www.googleapis.com/oauth2/v3/certs")
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

  for i := 0; i < set.Len(); i++ {
    key, ok := set.Key(i) // This retrieves the corresponding jwk.Key
    if !ok {
      log.Printf("failed to get key at index %d", i)
      return
    }

    // jws and jwe operations can be performed using jwk.Key, but you could also
    // covert it to their "raw" forms, such as *rsa.PrivateKey or *ecdsa.PrivateKey
    rawkeyV, err := jwk.Export[any](key)
    if err != nil {
      log.Printf("failed to create public key: %s", err)
      return
    }

    // You can create jwk.Key from a raw key, too
    fromRawKey, err := jwk.Import[jwk.Key](rawkeyV)
    if err != nil {
      log.Printf("failed to acquire raw key from jwk.Key: %s", err)
      return
    }

    // Keys can be serialized back to JSON
    jsonbuf, err := json.Marshal(key)
    if err != nil {
      log.Printf("failed to marshal key into JSON: %s", err)
      return
    }

    fromJSONKey, err := jwk.Parse(jsonbuf)
    if err != nil {
      log.Printf("failed to parse json: %s", err)
      return
    }
    _ = fromJSONKey
    _ = fromRawKey
  }
  // OUTPUT:
}

//nolint:govet
func Example_jwk_marshal_json() {
  // JWKs that inherently involve randomness such as RSA and EC keys are
  // not used in this example, because they may produce different results
  // depending on the environment.
  //
  // (In fact, even if you use a static source of randomness, tests may fail
  // because of internal changes in the Go runtime).

  raw := []byte("01234567890123456789012345678901234567890123456789ABCDEF")

  // This would create a symmetric key
  key, err := jwk.Import[jwk.SymmetricKey](raw)
  if err != nil {
    fmt.Printf("failed to create symmetric key: %s\n", err)
    return
  }

  key.Set(jwk.KeyIDKey, "mykey")

  buf, err := json.MarshalIndent(key, "", "  ")
  if err != nil {
    fmt.Printf("failed to marshal key into JSON: %s\n", err)
    return
  }
  fmt.Printf("%s\n", buf)

  // OUTPUT:
  // {
  //   "k": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODlBQkNERUY",
  //   "kid": "mykey",
  //   "kty": "oct"
  // }
}
```
source: [examples/jwk_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwk_example_test.go)
<!-- END INCLUDE -->

# Auto-refresh a key during a long-running process

<!-- INCLUDE(examples/jwk_cache_example_test.go) -->
```go
package examples_test

import (
  "context"
  "fmt"
  "time"

  "github.com/lestrrat-go/httprc/v3"

  "github.com/jwx-go/jwkcache/v4"
)

func Example_jwk_cache() {
  ctx, cancel := context.WithCancel(context.Background())
  defer cancel()

  const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

  // First, set up the `jwkcache.Cache` object. You need to pass it a
  // `context.Context` object to control the lifecycle of the background fetching goroutine.
  c, err := jwkcache.NewCache(ctx, httprc.NewClient())
  if err != nil {
    fmt.Printf("failed to create cache: %s\n", err)
    return
  }

  // Tell the cache that we only want to refresh this JWKS periodically.
  if err := c.Register(ctx, googleCerts); err != nil {
    fmt.Printf("failed to register google JWKS: %s\n", err)
    return
  }

  // Pretend that this is your program's main loop
MAIN:
  for {
    select {
    case <-ctx.Done():
      break MAIN
    default:
    }
    keyset, err := c.Lookup(ctx, googleCerts)
    if err != nil {
      fmt.Printf("failed to fetch google JWKS: %s\n", err)
      return
    }
    _ = keyset
    // The returned `keyset` will always be "reasonably" new.
    //
    // By "reasonably" we mean that we cannot guarantee that the keys will be refreshed
    // immediately after it has been rotated in the remote source. But it should be close\
    // enough, and should you need to forcefully refresh the token using the `(jwkcache.Cache).Refresh()` method.
    //
    // If refetching the keyset fails, a cached version will be returned from the previous
    // successful sync

    // Do interesting stuff with the keyset... but here, we just
    // sleep for a bit
    time.Sleep(time.Second)

    // Because we're a dummy program, we just cancel the loop now.
    // If this were a real program, you presumably loop forever
    cancel()
  }
  // OUTPUT:
}
```
source: [examples/jwk_cache_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwk_cache_example_test.go)
<!-- END INCLUDE -->
