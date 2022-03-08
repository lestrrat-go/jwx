# JWK [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/v2/jwk.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk)

Package jwk implements JWK as described in [RFC7517](https://tools.ietf.org/html/rfc7517).
If you are looking to use JWT wit JWKs, look no further than [github.com/lestrrat-go/jwx](../jwt).

* Parse and work with RSA/EC/Symmetric/OKP JWK types
  * Convert to and from JSON
  * Convert to and from raw key types (e.g. *rsa.PrivateKey)
* Ability to keep a JWKS fresh using *jwk.AutoRefersh

## Supported key types:

| kty | Curve                   | Go Key Type                                   |
|:----|:------------------------|:----------------------------------------------|
| RSA | N/A                     | rsa.PrivateKey / rsa.PublicKey (2)            |
| EC  | P-256<br>P-384<br>P-521<br>secp256k1 (1) | ecdsa.PrivateKey / ecdsa.PublicKey (2)        |
| oct | N/A                     | []byte                                        |
| OKP | Ed25519 (1)             | ed25519.PrivateKey / ed25519.PublicKey (2)    |
|     | X25519 (1)              | (jwx/)x25519.PrivateKey / x25519.PublicKey (2)|

* Note 1: Experimental
* Note 2: Either value or pointers accepted (e.g. rsa.PrivateKey or *rsa.PrivateKey)

# Documentation

Please read the [API reference](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk), or
the how-to style documentation on how to use JWK can be found in the [docs directory](../docs/04-jwk.md).

# Auto-Refresh a key during a long running process

```go
func ExampleAutoRefresh() {
	ctx, cancel := context.WithCancel(context.Background())

	const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`
	ar := jwk.NewAutoRefresh(ctx)

	// Tell *jwk.AutoRefresh that we only want to refresh this JWKS
	// when it needs to (based on Cache-Control or Expires header from
	// the HTTP response). If the calculated minimum refresh interval is less
	// than 15 minutes, don't go refreshing any earlier than 15 minutes.
	ar.Configure(googleCerts, jwk.WithMinRefreshInterval(15*time.Minute))

	// Refresh the JWKS once before getting into the main loop.
	// This allows you to check if the JWKS is available before we start
	// a long-running program
	_, err := ar.Refresh(ctx, googleCerts)
	if err != nil {
		fmt.Printf("failed to refresh google JWKS: %s\n", err)
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
		keyset, err := ar.Fetch(ctx, googleCerts)
		if err != nil {
			fmt.Printf("failed to fetch google JWKS: %s\n", err)
			return
		}
		_ = keyset

		// Do interesting stuff with the keyset... but here, we just
		// sleep for a bit
		time.Sleep(time.Second)

		// Because we're a dummy program, we just cancel the loop now.
		// If this were a real program, you prosumably loop forever
		cancel()
	}
	// OUTPUT:
}
```

Parse and use a JWK key:

```go

import (
  "encoding/json"
  "log"

  "github.com/lestrrat-go/jwx/v2/jwk"
)

func main() {
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
    fromJsonKey, err := jwk.Parse(jsonbuf)
    if err != nil {
      log.Printf("failed to parse json: %s", err)
      return
    }
    _ = fromJsonKey
    _ = fromRawKey
  }
}
```


