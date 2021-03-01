# github.com/lestrrat-go/jwx/jwt [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/jwt.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt)

Package jwt implements JSON Web Tokens as described in [RFC7519](https://tools.ietf.org/html/rfc7519).

* Convenience methods for oft-used keys ("aud", "sub", "iss", etc)
* Convenience functions to extract/parse from http.Request, http.Header, url.Values
* Ability to Get/Set arbitrary keys
* Conversion to and from JSON
* Generate signed tokens
* Verify signed tokens

# SYNOPSIS

More examples are located in the examples directory ([jwt_example_test.go](../examples/jwt_example_test.go))

# Verify a signed JWT

```go
  token, err := jwt.Parse(bytes.NewReader(payload), jwt.WithKeySet(keyset))
  if err != nil {
    fmt.Printf("failed to parse payload: %s\n", err)
  }
```

# Token Usage

```go
func ExampleJWT() {
  const aLongLongTimeAgo = 233431200

  t := jwt.New()
  t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/jwt`)
  t.Set(jwt.AudienceKey, `Golang Users`)
  t.Set(jwt.IssuedAtKey, time.Unix(aLongLongTimeAgo, 0))
  t.Set(`privateClaimKey`, `Hello, World!`)

  buf, err := json.MarshalIndent(t, "", "  ")
  if err != nil {
    fmt.Printf("failed to generate JSON: %s\n", err)
    return
  }

  fmt.Printf("%s\n", buf)
  fmt.Printf("aud -> '%s'\n", t.Audience())
  fmt.Printf("iat -> '%s'\n", t.IssuedAt().Format(time.RFC3339))
  if v, ok := t.Get(`privateClaimKey`); ok {
    fmt.Printf("privateClaimKey -> '%s'\n", v)
  }
  fmt.Printf("sub -> '%s'\n", t.Subject())

  key, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    log.Printf("failed to generate private key: %s", err)
    return
  }

  {
    // Signing a token (using raw rsa.PrivateKey)
    signed, err := jwt.Sign(t, jwa.RS256, key)
    if err != nil {
      log.Printf("failed to sign token: %s", err)
      return
    }
    _ = signed
  }

  {
    // Signing a token (using JWK)
    jwkKey, err := jwk.New(key)
    if err != nil {
      log.Printf("failed to create JWK key: %s", err)
      return
    }

    signed, err := jwt.Sign(t, jwa.RS256, jwkKey)
    if err != nil {
      log.Printf("failed to sign token: %s", err)
      return
    }
    _ = signed
  }
}
```

# OpenID Claims

`jwt` package can work with token types other than the default one.
For OpenID claims, use the token created by `openid.New()`, or
use the `jwt.WithOpenIDClaims()`. If you need to use other specialized
claims, use `jwt.WithToken()` to specify the exact token type

```go
func Example_openid() {
  const aLongLongTimeAgo = 233431200

  t := openid.New()
  t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/jwt`)
  t.Set(jwt.AudienceKey, `Golang Users`)
  t.Set(jwt.IssuedAtKey, time.Unix(aLongLongTimeAgo, 0))
  t.Set(`privateClaimKey`, `Hello, World!`)

  addr := openid.NewAddress()
  addr.Set(openid.AddressPostalCodeKey, `105-0011`)
  addr.Set(openid.AddressCountryKey, `日本`)
  addr.Set(openid.AddressRegionKey, `東京都`)
  addr.Set(openid.AddressLocalityKey, `港区`)
  addr.Set(openid.AddressStreetAddressKey, `芝公園 4-2-8`)
  t.Set(openid.AddressKey, addr)

  buf, err := json.MarshalIndent(t, "", "  ")
  if err != nil {
    fmt.Printf("failed to generate JSON: %s\n", err)
    return
  }
  fmt.Printf("%s\n", buf)

  t2, err := jwt.ParseBytes(buf, jwt.WithOpenIDClaims())
  if err != nil {
    fmt.Printf("failed to parse JSON: %s\n", err)
    return
  }
  if _, ok := t2.(openid.Token); !ok {
    fmt.Printf("using jwt.WithOpenIDClaims() creates an openid.Token instance")
    return
  }
}
```


