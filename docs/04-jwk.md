# Working with JWK

In this document we describe how to work with JWK using `github.com/lestrrat-go/jwx/v4/jwk`

* [Terminology](#terminology)
  * [JWK / Key](#jwk--key)
  * [JWK Set / Set](#jwk-set--set)
  * [Raw Key](#raw-key)
* [Parsing](#parsing)
  * [Parse a set](#parse-a-set)
  * [Parse a key](#parse-a-key)
  * [Parse a key or set in PEM format](#parse-a-key-or-a-set-in-pem-format)
  * [Parse a key from a file](#parse-a-key-from-a-file)
  * [Parse a key as a struct field](#parse-a-key-as-a-struct-field)
* [Construction](#construction)
  * [Using jwk.Import()](#using-jwkfromraw)
* [Fetching JWK Sets](#fetching-jwk-sets)
  * [Parse a key from a remote resource](#parse-a-key-from-a-remote-resource)
  * [Auto-refreshing remote keys](#auto-refreshing-remote-keys)
  * [Default Fetch Security Behavior](#default-fetch-security-behavior)
  * [Using Whitelists](#using-whitelists)
* [Working with jwk.Key](#working-with-jwkkey)
  * [Working with key-specific methods](#working-with-key-specific-methods)
  * [Setting values to fields](#setting-values-to-fields)
  * [Converting a jwk.Key to a raw key](#converting-a-jwkkey-to-a-raw-key)
  * [Filtering Keys with KeyFilter](#filtering-keys-with-keyfilter)

---

# Terminology

## JWK / Key

Used to describe a JWK key, possibly of type RSA, ECDSA, OKP, or Symmetric.

## JWK Set / Set

A "jwk" resource on the web can either contain a single JWK or an array of multiple JWKs.
The latter is called a JWK Set.

It is impossible to know what the resource contains beforehand, so functions like [`jwk.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Parse)
and [`jwk.ParseFS()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#ParseFS) returns a [`jwk.Set`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Set) by default.

## Raw Key

Used to describe the underlying raw key that a JWK represents. For example, an RSA JWK can
represent rsa.PrivateKey/rsa.PublicKey, ECDSA JWK can represent ecdsa.PrivateKey/ecdsa.PublicKey,
and so forth.

---

The table below shows the matrix of key types and their respective `jwk.Key` and "raw" types.
If given anything else, `jwk.Import` will return an error.

|           | `jwk.Key` Type                               | Raw Key Type                              |
|-----------|----------------------------------------------|-------------------------------------------|
| RSA       | `jwk.RSAPublicKey` / `jwk.RSAPrivateKey`     | `*rsa.PublicKey` / `*rsa.PublicKey`       |
| ECDSA     | `jwk.ECDSAPublicKey` / `jwk.ECDSAPrivateKey` | `*ecdsa.PublicKey` / `*ecdsa.PublicKey`   |
| OKP       | `jwk.OKPPublicKey` / `jwk.OKPPrivateKey`     | `ed25519.PublicKey` / `ed25519.PublicKey` |
| Symmetric | `jwk.SymmetricKey`                           | []byte                                    |

# Parsing

## Parse a set

If you have a key set, or are unsure if the source is a set or a single key, you should use [`jwk.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Parse)

<!-- INCLUDE(examples/jwk_parse_jwks_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwk_parse_jwks() {
  const src = `{
    "keys": [
      {"kty":"EC",
       "crv":"P-256",
       "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
       "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
       "use":"enc",
       "kid":"1"},
      {"kty":"RSA",
       "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
       "e":"AQAB",
       "alg":"RS256",
       "kid":"2011-04-29"}
    ]
  }`

  set, err := jwk.Parse([]byte(src))
  if err != nil {
    fmt.Printf("failed to parse JWKS: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(set)
  // OUTPUT:
  // {"keys":[{"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}]}
}
```
source: [examples/jwk_parse_jwks_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwk_parse_jwks_example_test.go)
<!-- END INCLUDE -->

## Parse a key

If you are sure that the source only contains a single key, you can use [`jwk.ParseKey()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#ParseKey)

<!-- INCLUDE(examples/jwk_parse_key_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwk_parse_key() {
  const src = `{
    "kty":"EC",
    "crv":"P-256",
    "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    "use":"enc",
    "kid":"1"
  }`

  key, err := jwk.ParseKeyAs[jwk.ECDSAPublicKey]([]byte(src))
  if err != nil {
    fmt.Printf("failed parse key: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(key)
  // OUTPUT:
  // {"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
}
```
source: [examples/jwk_parse_key_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwk_parse_key_example_test.go)
<!-- END INCLUDE -->

## Parse a key or a set in PEM format

Sometimes keys come in ASN.1 DER PEM format.  To parse these files, use the [`jwk.WithPEM()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#WithPEM) option.

<!-- INCLUDE(examples/jwk_parse_with_pem_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "os"

  "encoding/json"
  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwk_parse_with_pem() {
  const src = `-----BEGIN CERTIFICATE-----
MIIEljCCAn4CCQCTQBoGDvUbQTANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJK
UDAeFw0yMTA0MDEwMDE4MjhaFw0yMjA0MDEwMDE4MjhaMA0xCzAJBgNVBAYTAkpQ
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvws4H/OxVS3CW1zvUgjs
H443df9zCAblLVPPdeRD11Jl1OZmGS7rtQNjQyT5xGpeuk77ZJcfDNLx+mSEtiYQ
V37GD5MPz+RX3hP2azuLvxoBseaHE6kC8tkDed8buQLl1hgms15KmKnt7E8B+EK2
1YRj0w6ZzehIllTbbj6gDJ39kZ2VHdLf5+4W0Kyh9cM4aA0si2jQJQsohW2rpt89
b+IagFau+sxP3GFUjSEvyXIamXhS0NLWuAW9UvY/RwhnIo5BzmWZd/y2R305T+QT
rHtb/8aGav8mP3uDx6AMDp/0UMKFUO4mpoOusMnrplUPS4Lz6RNpffmrrglOEuRZ
/eSFzGL35OeL12aYSyrbFIVsc/aLs6MkoplsuSG6Zhx345h/dA2a8Ub5khr6bksP
zGLer+bpBrQQsy21unvCIUz5y7uaYhV3Ql+aIZ+dwpEgZ3xxAvdKKeoCGQlhH/4J
0sSuutUtuTLfrBSgLHJEv2HIzeynChL2CYR8aku/nL68VTdmSt9UY2JGMOf9U8BI
fGRpkWBvI8hddMxNm8wF+09WScaZ2JWu7qW/l2jOdgesPIWRg+Hm3NaRSHqAWCOq
VUJk9WkCAye0FPALqSvH0ApDKxNtGZb5JZRCW19TqmhgXbAqIf5hsxDaGIXZcW9S
CqapZPw7Ccs7BOKSFvmM9p0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAVfLzKRdA
0vFpAAp3K+CDth7mag2WWFOXjlWZ+4pxfEBX3k7erJbj6+qYuCvCHXqIZnK1kZzD
p4zwsu8t8RfSmPvxcm/jkvecG4DAIGTdhBVtAf/9PU3e4kZFQCqizicQABh+ZFKV
dDtkRebUA5EAvP8E/OrvrjYU5xnOxOZU3arVXJfKFjVD619qLuF8XXW5700Gdqwn
wBgasTCCg9+tniiscKaET1m9C4PdrlXuAIscV9tGcJ7yEAao1BXokyJ+mK6K2Zv1
z/vvUJA/rGMBJoUjnWrRHON1JMNou2KyRO6z37GpRnfPiNgFpGv2x3ZNeix7H4bP
6+x4KZWQir5047p9hV4YrqMXeULEj3uG2GnOgdR7+hiN39arFVr11DMgABmx19SM
VQpTHrC8a605wwCBWnkiYdNojLa5WgeEHdBghKVpWnx9frYgZcz2UP861el5Lg9R
j04wkGL4IORYiM7VHSHNU4u/dlgfQE1y0T+1CzXwquy4csvbBzBKnZ1o9ZBsOtWS
ox0RaBsMD70mvTwKKmlCSD5HgZZTC0CfGWk4dQp/Mct5Z0x0HJMEJCJzpgTn3CRX
z8CjezfckLs7UKJOlhu3OU9TFsiGDzSDBZdDWO1/uciJ/AAWeSmsBt8cKL0MirIr
c4wOvhbalcX0FqTM3mXCgMFRbibquhwdxbU=
-----END CERTIFICATE-----`

  key, err := jwk.ParseKeyAs[jwk.RSAPublicKey]([]byte(src), jwk.WithX509(true))
  if err != nil {
    fmt.Printf("failed to parse key in PEM format: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(key)
  // OUTPUT:
  // {"e":"AQAB","kty":"RSA","n":"vws4H_OxVS3CW1zvUgjsH443df9zCAblLVPPdeRD11Jl1OZmGS7rtQNjQyT5xGpeuk77ZJcfDNLx-mSEtiYQV37GD5MPz-RX3hP2azuLvxoBseaHE6kC8tkDed8buQLl1hgms15KmKnt7E8B-EK21YRj0w6ZzehIllTbbj6gDJ39kZ2VHdLf5-4W0Kyh9cM4aA0si2jQJQsohW2rpt89b-IagFau-sxP3GFUjSEvyXIamXhS0NLWuAW9UvY_RwhnIo5BzmWZd_y2R305T-QTrHtb_8aGav8mP3uDx6AMDp_0UMKFUO4mpoOusMnrplUPS4Lz6RNpffmrrglOEuRZ_eSFzGL35OeL12aYSyrbFIVsc_aLs6MkoplsuSG6Zhx345h_dA2a8Ub5khr6bksPzGLer-bpBrQQsy21unvCIUz5y7uaYhV3Ql-aIZ-dwpEgZ3xxAvdKKeoCGQlhH_4J0sSuutUtuTLfrBSgLHJEv2HIzeynChL2CYR8aku_nL68VTdmSt9UY2JGMOf9U8BIfGRpkWBvI8hddMxNm8wF-09WScaZ2JWu7qW_l2jOdgesPIWRg-Hm3NaRSHqAWCOqVUJk9WkCAye0FPALqSvH0ApDKxNtGZb5JZRCW19TqmhgXbAqIf5hsxDaGIXZcW9SCqapZPw7Ccs7BOKSFvmM9p0"}
}
```
source: [examples/jwk_parse_with_pem_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwk_parse_with_pem_example_test.go)
<!-- END INCLUDE -->

## Parse a key from a file

To parse keys stored in a file, [`jwk.ParseFS()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#ParseFS) can be used. 

<!-- INCLUDE(examples/jwk_parsefs_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"
  "path/filepath"

  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwk_ParseFS() {
  const src = `{
    "keys": [
      {"kty":"EC",
       "crv":"P-256",
       "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
       "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
       "use":"enc",
       "kid":"1"},
      {"kty":"RSA",
       "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
       "e":"AQAB",
       "alg":"RS256",
       "kid":"2011-04-29"}
    ]
  }`

  f, err := os.CreateTemp(``, `jwk_parsefs-*.jwk`)
  if err != nil {
    fmt.Printf("failed to create temporary file: %s\n", err)
    return
  }
  defer os.Remove(f.Name())

  fmt.Fprint(f, src)
  f.Close()

  key, err := jwk.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()))
  if err != nil {
    fmt.Printf("failed to parse key: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(key)

  // OUTPUT:
  // {"keys":[{"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}]}
}
```
source: [examples/jwk_parsefs_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwk_parsefs_example_test.go)
<!-- END INCLUDE -->

`jwk.ParseFS()` accepts the same options as [`jwk.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Parse), therefore you can read a PEM-encoded file via the following incantation:

<!-- INCLUDE(examples/jwk_parsefs_with_pem_example_test.go) -->
```go
package examples_test

import (
  "fmt"
  "os"
  "path/filepath"

  "encoding/json"
  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwk_ParseFS_with_pem() {
  const src = `-----BEGIN CERTIFICATE-----
MIIEljCCAn4CCQCTQBoGDvUbQTANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJK
UDAeFw0yMTA0MDEwMDE4MjhaFw0yMjA0MDEwMDE4MjhaMA0xCzAJBgNVBAYTAkpQ
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvws4H/OxVS3CW1zvUgjs
H443df9zCAblLVPPdeRD11Jl1OZmGS7rtQNjQyT5xGpeuk77ZJcfDNLx+mSEtiYQ
V37GD5MPz+RX3hP2azuLvxoBseaHE6kC8tkDed8buQLl1hgms15KmKnt7E8B+EK2
1YRj0w6ZzehIllTbbj6gDJ39kZ2VHdLf5+4W0Kyh9cM4aA0si2jQJQsohW2rpt89
b+IagFau+sxP3GFUjSEvyXIamXhS0NLWuAW9UvY/RwhnIo5BzmWZd/y2R305T+QT
rHtb/8aGav8mP3uDx6AMDp/0UMKFUO4mpoOusMnrplUPS4Lz6RNpffmrrglOEuRZ
/eSFzGL35OeL12aYSyrbFIVsc/aLs6MkoplsuSG6Zhx345h/dA2a8Ub5khr6bksP
zGLer+bpBrQQsy21unvCIUz5y7uaYhV3Ql+aIZ+dwpEgZ3xxAvdKKeoCGQlhH/4J
0sSuutUtuTLfrBSgLHJEv2HIzeynChL2CYR8aku/nL68VTdmSt9UY2JGMOf9U8BI
fGRpkWBvI8hddMxNm8wF+09WScaZ2JWu7qW/l2jOdgesPIWRg+Hm3NaRSHqAWCOq
VUJk9WkCAye0FPALqSvH0ApDKxNtGZb5JZRCW19TqmhgXbAqIf5hsxDaGIXZcW9S
CqapZPw7Ccs7BOKSFvmM9p0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAVfLzKRdA
0vFpAAp3K+CDth7mag2WWFOXjlWZ+4pxfEBX3k7erJbj6+qYuCvCHXqIZnK1kZzD
p4zwsu8t8RfSmPvxcm/jkvecG4DAIGTdhBVtAf/9PU3e4kZFQCqizicQABh+ZFKV
dDtkRebUA5EAvP8E/OrvrjYU5xnOxOZU3arVXJfKFjVD619qLuF8XXW5700Gdqwn
wBgasTCCg9+tniiscKaET1m9C4PdrlXuAIscV9tGcJ7yEAao1BXokyJ+mK6K2Zv1
z/vvUJA/rGMBJoUjnWrRHON1JMNou2KyRO6z37GpRnfPiNgFpGv2x3ZNeix7H4bP
6+x4KZWQir5047p9hV4YrqMXeULEj3uG2GnOgdR7+hiN39arFVr11DMgABmx19SM
VQpTHrC8a605wwCBWnkiYdNojLa5WgeEHdBghKVpWnx9frYgZcz2UP861el5Lg9R
j04wkGL4IORYiM7VHSHNU4u/dlgfQE1y0T+1CzXwquy4csvbBzBKnZ1o9ZBsOtWS
ox0RaBsMD70mvTwKKmlCSD5HgZZTC0CfGWk4dQp/Mct5Z0x0HJMEJCJzpgTn3CRX
z8CjezfckLs7UKJOlhu3OU9TFsiGDzSDBZdDWO1/uciJ/AAWeSmsBt8cKL0MirIr
c4wOvhbalcX0FqTM3mXCgMFRbibquhwdxbU=
-----END CERTIFICATE-----`

  f, err := os.CreateTemp(``, `jwk_parsefs_with_pem-*.jwk`)
  if err != nil {
    fmt.Printf("failed to create temporary file: %s\n", err)
    return
  }
  defer os.Remove(f.Name())

  fmt.Fprint(f, src)
  f.Close()

  key, err := jwk.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()), jwk.WithX509(true))
  if err != nil {
    fmt.Printf("failed to parse key in PEM format: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(key)
  // OUTPUT:
  // {"keys":[{"e":"AQAB","kty":"RSA","n":"vws4H_OxVS3CW1zvUgjsH443df9zCAblLVPPdeRD11Jl1OZmGS7rtQNjQyT5xGpeuk77ZJcfDNLx-mSEtiYQV37GD5MPz-RX3hP2azuLvxoBseaHE6kC8tkDed8buQLl1hgms15KmKnt7E8B-EK21YRj0w6ZzehIllTbbj6gDJ39kZ2VHdLf5-4W0Kyh9cM4aA0si2jQJQsohW2rpt89b-IagFau-sxP3GFUjSEvyXIamXhS0NLWuAW9UvY_RwhnIo5BzmWZd_y2R305T-QTrHtb_8aGav8mP3uDx6AMDp_0UMKFUO4mpoOusMnrplUPS4Lz6RNpffmrrglOEuRZ_eSFzGL35OeL12aYSyrbFIVsc_aLs6MkoplsuSG6Zhx345h_dA2a8Ub5khr6bksPzGLer-bpBrQQsy21unvCIUz5y7uaYhV3Ql-aIZ-dwpEgZ3xxAvdKKeoCGQlhH_4J0sSuutUtuTLfrBSgLHJEv2HIzeynChL2CYR8aku_nL68VTdmSt9UY2JGMOf9U8BIfGRpkWBvI8hddMxNm8wF-09WScaZ2JWu7qW_l2jOdgesPIWRg-Hm3NaRSHqAWCOqVUJk9WkCAye0FPALqSvH0ApDKxNtGZb5JZRCW19TqmhgXbAqIf5hsxDaGIXZcW9SCqapZPw7Ccs7BOKSFvmM9p0"}]}
}
```
source: [examples/jwk_parsefs_with_pem_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwk_parsefs_with_pem_example_test.go)
<!-- END INCLUDE -->

## Parse a key as a struct field

As `jwk.Key` is an interface, it can't directly be used as an argument in `json.Unmarshal`.
For example, the following would fail:

```go
var key jwk.Key
json.Unmarshal(data, &key) // error
```

This poses a problem when you want to use `jwk.Key` as a struct field in another struct
that needs to handle `json.Unmarshal`. To overcome this, you can either define a custom
`UnmarshalJSON([]byte) error` for your container struct, or you can use a "proxy" struct
that will intercept the field holding the `jwk.Key`.

<!-- INCLUDE(examples/jwk_struct_field_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v4/jwk"
)

type Container struct {
  Key jwk.Key `json:"key"`
}

// This is only one way to parse a struct field whose dynamic
// type is unknown at compile time. In this example we use
// a proxy/wrapper to trick `Container` from attempting to
// parse the `.Key` field, and intercept the value that
// would have gone into the `Container` struct into
// `Proxy` struct's `.Key` struct field
type Proxy struct {
  Container
  Key json.RawMessage `json:"key"`
}

func Example_jwk_struct_field() {
  const src = `{
    "key": {
      "kty":"EC",
      "crv":"P-256",
      "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      "use":"enc",
      "kid":"1"
    }
  }`

  var p Proxy
  if err := json.Unmarshal([]byte(src), &p); err != nil {
    fmt.Printf("failed to unmarshal from JSON: %s\n", err)
    return
  }

  // Parse the intercepted `Proxy.Key` as a `jwk.Key`
  // and assign it to `Container.Key`
  key, err := jwk.ParseKey(p.Key)
  if err != nil {
    fmt.Printf("failed to parse key: %s\n", err)
    return
  }
  p.Container.Key = key

  json.NewEncoder(os.Stdout).Encode(p.Container)
  // OUTPUT:
  // {"key":{"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}}
}
```
source: [examples/jwk_struct_field_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwk_struct_field_example_test.go)
<!-- END INCLUDE -->

# Construction

## Using jwk.Import()

Users can create a new key from scratch using [`jwk.Import()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Import).

[`jwk.Import()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Import) requires the raw key as its argument.
There are other ways to creating keys from a raw key, but they require knowing its type in advance.
Use [`jwk.Import()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Import) when you have a key type which you do not know its underlying type in advance.

It automatically creates the appropriate underlying key based on the given argument type.
The returned key has already passed `Validate()`, so malformed raw keys fail at
import time instead of being returned for later validation.

| Argument Type | Key Type | Note |
|---------------|----------|------|
| []byte        | Symmetric Key | |
| ecdsa.PrivateKey | ECDSA Private Key | Argument may also be a pointer |
| ecdsa.PubliKey | ECDSA Public Key | Argument may also be a pointer |
| rsa.PrivateKey | RSA Private Key | Argument may also be a pointer |
| rsa.PubliKey | RSA Public Key | Argument may also be a pointer |
| x25519.PrivateKey | OKP Private Key | |
| x25519.PubliKey | OKP Public Key | |

<!-- INCLUDE(examples/jwk_import_example_test.go) -->
```go
package examples_test

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwk_import() {
  // First, THIS IS THE WRONG WAY TO USE jwk.Import().
  //
  // Assume that the file contains a JWK in JSON format
  //
  //  buf, _ := os.ReadFile(file)
  //  key, _ := jwk.Import[jwk.Key](buf)
  //
  // This is not right, because jwk.Import() determines the type of
  // `jwk.Key` to create based on the TYPE of the argument.
  // In this case the type of `buf` is always []byte, and therefore
  // it will always create a symmetric key.
  //
  // What you want to do is to _parse_ `buf`.
  //
  //  keyset, _ := jwk.Parse(buf)
  //  key, _    := jwk.ParseKey(buf)
  //
  // See other examples in examples/jwk_parse_key_example_test.go and
  // examples/jwk_parse_jwks_example_test.go

  // []byte -> jwk.SymmetricKey
  //
  // Use the concrete type parameter to get the typed key directly.
  {
    raw := []byte("Lorem Ipsum")
    key, err := jwk.Import[jwk.SymmetricKey](raw)
    if err != nil {
      fmt.Printf("failed to create symmetric key: %s\n", err)
      return
    }
    _ = key
  }

  // *rsa.PrivateKey -> jwk.RSAPrivateKey
  // *rsa.PublicKey  -> jwk.RSAPublicKey
  {
    raw, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
      fmt.Printf("failed to generate new RSA private key: %s\n", err)
      return
    }

    key, err := jwk.Import[jwk.RSAPrivateKey](raw)
    if err != nil {
      fmt.Printf("failed to create RSA private key: %s\n", err)
      return
    }
    _ = key
    // PublicKey is omitted for brevity
  }

  // *ecdsa.PrivateKey -> jwk.ECDSAPrivateKey
  // *ecdsa.PublicKey  -> jwk.ECDSAPublicKey
  {
    raw, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    if err != nil {
      fmt.Printf("failed to generate new ECDSA private key: %s\n", err)
      return
    }

    key, err := jwk.Import[jwk.ECDSAPrivateKey](raw)
    if err != nil {
      fmt.Printf("failed to create ECDSA private key: %s\n", err)
      return
    }
    _ = key
    // PublicKey is omitted for brevity
  }

  // OUTPUT:
}
```
source: [examples/jwk_import_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwk_import_example_test.go)
<!-- END INCLUDE -->

> Warning: `jwk.Import[jwk.SymmetricKey]([]byte(...))` only requires a non-empty octet string. When the key is used with a specific algorithm, size it yourself: use at least 32/48/64 bytes for `HS256`/`HS384`/`HS512`; 16/24/32 bytes for `A128KW`/`A192KW`/`A256KW`, `A128GCM`/`A192GCM`/`A256GCM`, and `A128GCMKW`/`A192GCMKW`/`A256GCMKW`; and 32/48/64 bytes for `A128CBC-HS256`/`A192CBC-HS384`/`A256CBC-HS512`.

# Fetching JWK Sets

HTTP-based JWK Set retrieval has moved out of the core `jwk` package. The main jwx module no longer depends on `net/http` or [`httprc`](https://github.com/lestrrat-go/httprc), and there is no `jwk.Fetch` function. All HTTP fetching lives in the [`github.com/jwx-go/jwkfetch/v4`](https://github.com/jwx-go/jwkfetch) companion.

The `jwk` package still defines the minimal `jwk.Fetcher` interface:

```go
type Fetcher interface {
    Fetch(ctx context.Context, url string) (Set, error)
}
```

…but there is no in-package implementation. You get a concrete implementation from `jwkfetch`, which offers two complementary types:

- **`jwkfetch.Client`** — one-shot HTTPS fetch. Use for ad-hoc retrievals and for `jku`-style verification where the URL comes from an untrusted JWS header.
- **`jwkfetch.Cache`** — background-refreshed JWKS store backed by [`httprc`](https://github.com/lestrrat-go/httprc). Use for a small, trusted set of issuer JWKS endpoints where amortizing fetch cost matters.

Both implement `jwk.Fetcher` and are **closed structs** constructed via functional options.

```go
import (
  "github.com/jwx-go/jwkfetch/v4"
  "github.com/lestrrat-go/httprc/v3"
)

// --- one-shot fetch (trusted URL) ---
client := jwkfetch.NewClient()
set, err := client.Fetch(ctx, "https://issuer.example/jwks.json")

// --- one-shot fetch (jku-style, URL is untrusted) ---
jkuClient := jwkfetch.NewClient(
  jwkfetch.WithWhitelist(
    jwkfetch.NewMapWhitelist().Add("https://issuer.example/jwks.json"),
  ),
)
_, err := jws.Verify(signed, jws.WithVerifyAuto(jkuClient))

// --- background-refreshed cache ---
cache, _ := jwkfetch.NewCache(ctx, httprc.NewClient())
_ = cache.Register(ctx, "https://issuer.example/jwks.json",
  jwkfetch.WithMinInterval(15*time.Minute),
)
// Both types satisfy jwk.Fetcher and can be wired into jws.WithVerifyAuto / jwt.WithVerifyAuto.
_, err = jws.Verify(signed, jws.WithVerifyAuto(cache))
```

## Default security behavior

`jwkfetch.NewClient()` with no `WithWhitelist` permits every URL. This is the right default when the URL you're fetching is a compile-time constant or comes from trusted configuration — the trust decision is already made at the call site, and a whitelist would be redundant.

**For `jku`-style verification, or any fetch whose URL comes from an untrusted source, you MUST configure a restrictive `Whitelist` on the fetcher.** jwx itself does not prepend a default-deny wrapper around the fetcher — a hostile peer who controls the URL can otherwise point the library at any destination the fetcher can reach (SSRF) or hand you a JWKS their own server controls and have their keys accepted as "the issuer's keys":

```go
jkuClient := jwkfetch.NewClient(
  jwkfetch.WithWhitelist(
    jwkfetch.NewMapWhitelist().Add("https://issuer.example/jwks.json"),
  ),
)
```

A restrictive `Whitelist` is applied to **every URL the Client contacts**, including the targets of 3xx redirects. A hostile JWKS host cannot bypass the allowlist by 302-ing into an off-list URL.

The default HTTP client (`jwkfetch.DefaultHTTPClient()`) applies a 30-second timeout, a 5-redirect cap, and a redirect policy that blocks HTTPS→HTTP scheme downgrades. If you bring your own `*http.Client` via `jwkfetch.WithHTTPClient(...)`, wrap it with `jwkfetch.WrapHTTPClientDefaults(...)` first to keep those protections. For full SSRF defense (private-IP blocking, DNS rebinding prevention), supply a `*http.Client` whose `Transport.DialContext` validates resolved addresses.

## Whitelist types

Pass any implementation of `jwkfetch.Whitelist` to `jwkfetch.WithWhitelist`:

- `jwkfetch.InsecureWhitelist{}` — allow every URL (the default when `WithWhitelist` isn't passed)
- `jwkfetch.BlockAllWhitelist{}` — deny every URL (useful for tests, safety assertions)
- `jwkfetch.NewMapWhitelist().Add(url1).Add(url2)` — fixed allow-list of exact URLs
- `jwkfetch.NewRegexpWhitelist().Add(pattern)` — pattern-based allow-list
- `jwkfetch.WhitelistFunc(func(string) bool)` — custom predicate

All the restrictive types fail closed: a URL that doesn't match any listed entry / pattern / predicate is rejected with a `WhitelistError`, for both the initial URL and every redirect target. Whitelist rejections can be detected with `errors.Is(err, jwkfetch.WhitelistError())`.

The `Whitelist` concept applies to `Client` only. `Cache` has no `Whitelist` field — it's a cache, and the set of URLs it will ever contact is exactly the set you passed to `Register`. Trying to pass `WithWhitelist` to `NewCache` is a compile-time error.

See the [`jwkfetch` section of the extensions doc](./10-extensions.md#http-jwk-set-retrieval-jwkfetch) and the [module README](https://github.com/jwx-go/jwkfetch) for the full API reference, including allowlist patterns and the regex footguns to avoid.

# Working with jwk.Key

## [Working with key-specific methods]

While you would almost always be able to get away with working with just the `jwk.Key` interface, there might be times when you want to get to methods that are specific to a particular key type, such as an RSA key.

In these cases it is possible to convert their types and get a more specific interface, such as `jwk.RSAPrivateKey`

<!-- INCLUDE(examples/jwk_key_specific_methods_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_jwk_key_specific_metehods() {
  raw, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Printf("failed to generate RSA private key: %s\n", err)
    return
  }

  // Use the concrete type parameter to get the typed key directly,
  // instead of importing as jwk.Key and then type-asserting.
  rsakey, err := jwk.Import[jwk.RSAPrivateKey](raw)
  if err != nil {
    fmt.Printf("failed to create jwk.RSAPrivateKey from RSA private key: %s\n", err)
    return
  }

  // Once you have the typed key, you can access RSA-specific methods
  // without a type assertion.
  //
  // We won't print these values, because each time they are
  // generated the contents will be different, and thus our
  // tests would fail.
  _, _ = rsakey.D()
  _, _ = rsakey.DP()
  _, _ = rsakey.DQ()
  _, _ = rsakey.E()
  _, _ = rsakey.N()
  _, _ = rsakey.P()
  _, _ = rsakey.Q()
  _, _ = rsakey.QI()
  // OUTPUT:
  //
}
```
source: [examples/jwk_key_specific_methods_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwk_key_specific_methods_example_test.go)
<!-- END INCLUDE -->

## Setting values to fields

Using [`jwk.Import()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Import) allows you to create a key whose fields have been properly populated, but sometimes there are other fields that you may want to populate in a key, such as`kid`, or other custom fields.

These fields can all be set using the [`jwk.Set()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Set) method.

The [`jwk.Set()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Set) method takes the name of the key and a value to be associated with it. Some predefined keys have specific types (in which type checks are enforced), and others don't.

[`jwk.Set()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Set) may not alter the Key Type (`kty`) field of a key.

The `jwk` package defines field key names for predefined keys as constants, so you won't ever have to bang your head against the wall after finding out that you have a typo.

```go
key.Set(jwk.KeyIDKey, `my-awesome-key`)
key.Set(`my-custom-field`, `unbelievable-value`)
```

## Converting a jwk.Key to a raw key

As discussed in [Terminology](#terminology), this package calls the "original" keys (e.g. `rsa.PublicKey`, `ecdsa.PrivateKey`, etc.) "raw" keys. To obtain a raw key from a  [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Key) object, use the [`Raw()`](https://github.com/github.com/lestrrat-go/jwx/v4/jwk#Raw) method.

```go
key, _ := jwk.ParseKey(src)

var raw interface{}
if err := key.Raw(&raw); err != nil {
  ...
}
```

In the above example, `raw` contains whatever the [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#Key) represents.
If `key` represents an RSA key, it will contain either a `rsa.PublicKey` or `rsa.PrivateKey`. If it represents an ECDSA key, an `ecdsa.PublicKey`, or `ecdsa.PrivateKey`, etc.

If the only operation that you are performing is to grab the raw key out of a JSON JWK, use [`jwk.ParseRawKey`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#ParseRawKey)

```go
var raw interface{}
if err := jwk.ParseRawKey(src, &raw); err != nil {
  ...
}
```

## Filtering Keys with KeyFilter

The [`jwk.KeyFilter`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#KeyFilter) interface provides a mechanism to selectively include or exclude specific fields when working with JWK keys. This is useful when you need to serialize keys with only certain fields, or when you want to create clean representations of keys for specific purposes.

KeyFilter objects provide two methods:
- `Filter()`: Returns a new key containing only the fields that should be included
- `Reject()`: Returns a new key with specified fields excluded

### Standard Field Filters

For convenience, the library provides pre-defined filters that include standard fields for each key type:

- [`jwk.RSAStandardFieldsFilter()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#RSAStandardFieldsFilter) - for RSA keys
- [`jwk.ECDSAStandardFieldsFilter()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#ECDSAStandardFieldsFilter) - for ECDSA keys  
- [`jwk.OKPStandardFieldsFilter()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#OKPStandardFieldsFilter) - for OKP keys
- [`jwk.SymmetricStandardFieldsFilter()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk#SymmetricStandardFieldsFilter) - for symmetric keys

These functions return filters configured to include the standard fields defined in the JWK specification for each key type.
