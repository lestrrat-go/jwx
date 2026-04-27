# JWK [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/v4/jwk.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk)

Package jwk implements JWK as described in [RFC 7517](https://tools.ietf.org/html/rfc7517).

## Supported key types:

| kty | Curve | Go Key Type |
|:----|:------|:------------|
| RSA | N/A | `rsa.PrivateKey` / `rsa.PublicKey` (*) |
| EC  | P-256, P-384, P-521 | `ecdsa.PrivateKey` / `ecdsa.PublicKey` (*) |
| oct | N/A | `[]byte` |
| OKP | Ed25519, X25519, X448 | `ed25519.PrivateKey` / `ed25519.PublicKey`, `x25519.PrivateKey` / `x25519.PublicKey` (*) |
| AKP | post-quantum (see extensions) | populated by extension modules |

(*) Either value or pointers accepted (e.g. `rsa.PrivateKey` or `*rsa.PrivateKey`)

Additional key types available via [extension modules](../docs/10-extensions.md): secp256k1 (ES256K), Ed448, ML-DSA, ML-KEM.

## Parse and use a JWK key

<!-- INCLUDE(examples/jwk_example_test.go) -->
```go
package examples_test

import (
  "context"
  "encoding/json"
  "fmt"
  "net/http"
  "net/http/httptest"
  "os"
  "strings"

  "github.com/jwx-go/jwkfetch/v4"
  "github.com/lestrrat-go/jwx/v4/jwk"
)

// googleJWKSURL is the canonical OAuth 2.0 / OpenID Connect JWKS
// endpoint for accounts.google.com. Real production code calling
// jwkfetch against Google would pass this string verbatim.
const googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

// googleJWKSFixture is a small inline JWK Set used by the example
// when running offline (the default). It mirrors the shape Google
// returns — two RSA public keys with kid + alg — but the key
// material is fake.
const googleJWKSFixture = `{
  "keys":[
    {"kty":"RSA",
     "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
     "e":"AQAB",
     "alg":"RS256",
     "kid":"example-key-1"},
    {"kty":"RSA",
     "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
     "e":"AQAB",
     "alg":"RS256",
     "kid":"example-key-2"}
  ]
}`

// roundTripFunc adapts a function value to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
  return f(r)
}

func Example_jwk_usage() {
  // HTTP JWK Set retrieval lives in the jwkfetch extension module
  // (github.com/jwx-go/jwkfetch). For a one-shot fetch, use
  // jwkfetch.NewClient; for background-refreshed caching of a
  // fixed set of trusted URLs, use jwkfetch.NewCache.
  //
  // In production this single line is all you need:
  //
  //   client := jwkfetch.NewClient()
  //
  // The branch below stands up a local httptest server and routes
  // requests for the Google URL through it, so the example does
  // not depend on Google being reachable in CI. Set
  // JWX_EXAMPLE_FETCH_LIVE=1 in your environment to skip the local
  // server and hit https://www.googleapis.com/oauth2/v3/certs
  // directly.
  var client *jwkfetch.Client
  if os.Getenv("JWX_EXAMPLE_FETCH_LIVE") != "" {
    client = jwkfetch.NewClient()
  } else {
    srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
      fmt.Fprint(w, googleJWKSFixture)
    }))
    defer srv.Close()

    // Route every request through the local httptest server,
    // regardless of the URL the example passes to Fetch. The
    // Fetch call below stays byte-identical to production code
    // against Google.
    hc := srv.Client()
    origTransport := hc.Transport
    target := strings.TrimPrefix(srv.URL, "https://")
    hc.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
      req.URL.Host = target
      return origTransport.RoundTrip(req)
    })
    client = jwkfetch.NewClient(jwkfetch.WithHTTPClient(hc))
  }

  set, err := client.Fetch(context.Background(), googleJWKSURL)
  if err != nil {
    fmt.Printf("failed to fetch JWKS: %s\n", err)
    return
  }

  // Key sets can be serialized back to JSON.
  if _, err := json.Marshal(set); err != nil {
    fmt.Printf("failed to marshal key set into JSON: %s\n", err)
    return
  }

  for i := 0; i < set.Len(); i++ {
    key, ok := set.Key(i) // This retrieves the corresponding jwk.Key
    if !ok {
      fmt.Printf("failed to get key at index %d\n", i)
      return
    }

    // jws and jwe operations can be performed using jwk.Key, but you could also
    // convert it to its "raw" form, such as *rsa.PrivateKey or *ecdsa.PrivateKey.
    rawkeyV, err := jwk.Export[any](key)
    if err != nil {
      fmt.Printf("failed to export to raw key: %s\n", err)
      return
    }

    // You can create jwk.Key from a raw key, too.
    fromRawKey, err := jwk.Import[jwk.Key](rawkeyV)
    if err != nil {
      fmt.Printf("failed to import raw key into jwk.Key: %s\n", err)
      return
    }

    // Keys can be serialized back to JSON.
    jsonbuf, err := json.Marshal(key)
    if err != nil {
      fmt.Printf("failed to marshal key into JSON: %s\n", err)
      return
    }

    fromJSONKey, err := jwk.Parse(jsonbuf)
    if err != nil {
      fmt.Printf("failed to parse json: %s\n", err)
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

  "github.com/jwx-go/jwkfetch/v4"
)

func Example_jwk_cache() {
  ctx, cancel := context.WithCancel(context.Background())
  defer cancel()

  const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

  // First, set up the `jwkfetch.Cache` object. You need to pass it a
  // `context.Context` object to control the lifecycle of the background fetching goroutine.
  c, err := jwkfetch.NewCache(ctx, httprc.NewClient())
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
    // enough, and should you need to forcefully refresh the token using the `(jwkfetch.Cache).Refresh()` method.
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
