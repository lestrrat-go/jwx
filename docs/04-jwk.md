# Working with JWK

In this document we describe how to work with JWK using `github.com/lestrrat-go/jwx/v2/jwk`

* [Terminology](#terminology)
  * [JWK / Key](#jwk--key)
  * [JWK Set / Set](#jwk-set--set)
  * [Raw Key](#raw-key)
* [Parsing](#parsing)
  * [Parse a set](#parse-a-set)
  * [Parse a key](#parse-a-key)
  * [Parse a key or set in PEM format](#parse-a-key-or-a-set-in-pem-format)
  * [Parse a key from a file](#parse-a-key-from-a-file)
  * [Parse a key from a remote resource](#parse-a-key-from-a-remote-resource)
* [Construction](#construction)
  * [Using jwk.New()](#using-jwknew)
  * [Construct a specific key type from scratch](#construct-a-specific-key-type-from-scratch)
  * [Construct a specific key type from a raw key](#construct-a-specific-key-type-from-a-raw-key)
* [Setting values to fields](#setting-values-to-fields)
* [Fetching JWK Sets](#fetching-jwk-sets)
  * [Fetching a JWK Set once](#fetching-a-jwk-set-once)
  * [Auto-refreshing remote keys](#auto-refreshing-remote-keys)
  * [Using Whitelists](#using-whitelists)
* [Converting a jwk.Key to a raw key](#converting-a-jwkkey-to-a-raw-key)

---

# Terminology

## JWK / Key

Used to describe a JWK key, possibly of typeRSA, ECDSA, OKP, or Symmetric.

## JWK Set / Set

A "jwk" resource on the web can either contain a single JWK or an array of multiple JWKs.
The latter is called a JWK Set.

It is impossible to know what the resource contains beforehand, so functions like [`jwk.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Parse)
and [`jwk.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#ReadFile) returns a [`jwk.Set`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Set) by default.

## Raw Key

Used to describe the underlying raw key that a JWK represents. For example, an RSA JWK can
represent rsa.PrivateKey/rsa.PublicKey, ECDSA JWK can represent ecdsa.PrivateKey/ecdsa.PublicKey,
and so forth

# Parsing

## Parse a set

If you have a key set, or are unsure if the source is a set or a single key, you should use [`jwk.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Parse)

<!-- INCLUDE(examples/jwk_parse_jwks_example_test.go) -->
```go
package examples

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_ParseJWKS() {
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
source: [examples/jwk_parse_jwks_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwk_parse_jwks_example_test.go)
<!-- END INCLUDE -->

## Parse a key

If you are sure that the source only contains a single key, you can use [`jwk.ParseKey()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#ParseKey)

<!-- INCLUDE(examples/jwk_parse_key_example_test.go) -->
```go
package examples

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_ParseKey() {
  const src = `{
    "kty":"EC",
    "crv":"P-256",
    "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    "use":"enc",
    "kid":"1"
  }`

  key, err := jwk.ParseKey([]byte(src))
  if err != nil {
    fmt.Printf("failed parse key: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(key)
  // OUTPUT:
  // {"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
}
```
source: [examples/jwk_parse_key_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwk_parse_key_example_test.go)
<!-- END INCLUDE -->

## Parse a key or a set in PEM format

Sometimes keys come in ASN.1 DER PEM format.  To parse these files, use the [`jwk.WithPEM()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#WithPEM) option.

<!-- INCLUDE(examples/jwk_parse_with_pem_example_test.go) -->
```go
package examples

import (
  "fmt"
  "os"

  "github.com/lestrrat-go/jwx/v2/internal/json"
  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_ParseWithPEM() {
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

  key, err := jwk.ParseKey([]byte(src), jwk.WithPEM(true))
  if err != nil {
    fmt.Printf("failed to parse key in PEM format: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(key)
  // OUTPUT:
  // {"e":"AQAB","kty":"RSA","n":"vws4H_OxVS3CW1zvUgjsH443df9zCAblLVPPdeRD11Jl1OZmGS7rtQNjQyT5xGpeuk77ZJcfDNLx-mSEtiYQV37GD5MPz-RX3hP2azuLvxoBseaHE6kC8tkDed8buQLl1hgms15KmKnt7E8B-EK21YRj0w6ZzehIllTbbj6gDJ39kZ2VHdLf5-4W0Kyh9cM4aA0si2jQJQsohW2rpt89b-IagFau-sxP3GFUjSEvyXIamXhS0NLWuAW9UvY_RwhnIo5BzmWZd_y2R305T-QTrHtb_8aGav8mP3uDx6AMDp_0UMKFUO4mpoOusMnrplUPS4Lz6RNpffmrrglOEuRZ_eSFzGL35OeL12aYSyrbFIVsc_aLs6MkoplsuSG6Zhx345h_dA2a8Ub5khr6bksPzGLer-bpBrQQsy21unvCIUz5y7uaYhV3Ql-aIZ-dwpEgZ3xxAvdKKeoCGQlhH_4J0sSuutUtuTLfrBSgLHJEv2HIzeynChL2CYR8aku_nL68VTdmSt9UY2JGMOf9U8BIfGRpkWBvI8hddMxNm8wF-09WScaZ2JWu7qW_l2jOdgesPIWRg-Hm3NaRSHqAWCOqVUJk9WkCAye0FPALqSvH0ApDKxNtGZb5JZRCW19TqmhgXbAqIf5hsxDaGIXZcW9SCqapZPw7Ccs7BOKSFvmM9p0"}
}
```
source: [examples/jwk_parse_with_pem_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwk_parse_with_pem_example_test.go)
<!-- END INCLUDE -->

## Parse a key from a file

To parse keys stored in a file, [`jwk.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#ReadFile) can be used. 

<!-- INCLUDE(examples/jwk_readfile_example_test.go) -->
```go
package examples_test

import (
  "encoding/json"
  "fmt"
  "io/ioutil"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_ReadFile() {
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

  f, err := ioutil.TempFile(``, `jwk_readfile-*.jwk`)
  if err != nil {
    fmt.Printf("failed to create temporary file: %s\n", err)
    return
  }
  defer os.Remove(f.Name())

  fmt.Fprintf(f, src)
  f.Close()

  key, err := jwk.ReadFile(f.Name())
  if err != nil {
    fmt.Printf("failed to parse key: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(key)

  // OUTPUT:
  // {"keys":[{"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}]}
}
```
source: [examples/jwk_readfile_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwk_readfile_example_test.go)
<!-- END INCLUDE -->

`jwk.ReadFile()` accepts the same options as [`jwk.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Parse), therefore you can read a PEM-encoded file via the following incantation:

<!-- INCLUDE(examples/jwk_readfile_with_pem_example_test.go) -->
```go
package examples

import (
  "fmt"
  "io/ioutil"
  "os"

  "github.com/lestrrat-go/jwx/v2/internal/json"
  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_ReadFileWithPEM() {
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

  f, err := ioutil.TempFile(``, `jwk_readfile_with_pem-*.jwk`)
  if err != nil {
    fmt.Printf("failed to create temporary file: %s\n", err)
    return
  }
  defer os.Remove(f.Name())

  fmt.Fprintf(f, src)
  f.Close()

  key, err := jwk.ReadFile(f.Name(), jwk.WithPEM(true))
  if err != nil {
    fmt.Printf("failed to parse key in PEM format: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(key)
  // OUTPUT:
  // {"keys":[{"e":"AQAB","kty":"RSA","n":"vws4H_OxVS3CW1zvUgjsH443df9zCAblLVPPdeRD11Jl1OZmGS7rtQNjQyT5xGpeuk77ZJcfDNLx-mSEtiYQV37GD5MPz-RX3hP2azuLvxoBseaHE6kC8tkDed8buQLl1hgms15KmKnt7E8B-EK21YRj0w6ZzehIllTbbj6gDJ39kZ2VHdLf5-4W0Kyh9cM4aA0si2jQJQsohW2rpt89b-IagFau-sxP3GFUjSEvyXIamXhS0NLWuAW9UvY_RwhnIo5BzmWZd_y2R305T-QTrHtb_8aGav8mP3uDx6AMDp_0UMKFUO4mpoOusMnrplUPS4Lz6RNpffmrrglOEuRZ_eSFzGL35OeL12aYSyrbFIVsc_aLs6MkoplsuSG6Zhx345h_dA2a8Ub5khr6bksPzGLer-bpBrQQsy21unvCIUz5y7uaYhV3Ql-aIZ-dwpEgZ3xxAvdKKeoCGQlhH_4J0sSuutUtuTLfrBSgLHJEv2HIzeynChL2CYR8aku_nL68VTdmSt9UY2JGMOf9U8BIfGRpkWBvI8hddMxNm8wF-09WScaZ2JWu7qW_l2jOdgesPIWRg-Hm3NaRSHqAWCOqVUJk9WkCAye0FPALqSvH0ApDKxNtGZb5JZRCW19TqmhgXbAqIf5hsxDaGIXZcW9SCqapZPw7Ccs7BOKSFvmM9p0"}]}
}
```
source: [examples/jwk_readfile_with_pem_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwk_readfile_with_pem_example_test.go)
<!-- END INCLUDE -->

## Parse a key from a remote resource

To parse keys stored in a remote location pointed by a HTTP(s) URL, use [`jwk.Fetch()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Fetch)

If you are going to be using this key repeatedly in a long running process, consider using [`jwk.AutoRefresh`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#AutoRefresh) described elsewhere in this document.

<!-- INCLUDE(examples/jwk_fetch_example_test.go) -->
```go
package examples

import (
  "context"
  "encoding/json"
  "fmt"
  "net/http"
  "net/http/httptest"
  "os"

  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_Fetch() {
  srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, `{
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
    }`)
  }))
  defer srv.Close()

  set, err := jwk.Fetch(
    context.Background(),
    srv.URL,
    // This is necessary because httptest.Server is using a custom certificate
    jwk.WithHTTPClient(srv.Client()),
  )
  if err != nil {
    fmt.Printf("failed to fetch JWKS: %s\n", err)
    return
  }

  json.NewEncoder(os.Stdout).Encode(set)
  // OUTPUT:
  // {"keys":[{"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}]}
}
```
source: [examples/jwk_fetch_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwk_fetch_example_test.go)
<!-- END INCLUDE -->

# Construction

## Using jwk.New()

Users can create a new key from scratch using [`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#New).

[`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#New) requires the raw key as its argument.
There are other ways to creating keys from a raw key, but they require knowing its type in advance.
Use [`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#New) when you have a key type which you do not know its underlying type in advance.

It automatically creates the appropriate underlying key based on the given argument type.

| Argument Type | Key Type | Note |
|---------------|----------|------|
| []byte        | Symmetric Key | |
| ecdsa.PrivateKey | ECDSA Private Key | Argument may also be a pointer |
| ecdsa.PubliKey | ECDSA Public Key | Argument may also be a pointer |
| rsa.PrivateKey | RSA Private Key | Argument may also be a pointer |
| rsa.PubliKey | RSA Public Key | Argument may also be a pointer |
| x25519.PrivateKey | OKP Private Key | |
| x25519.PubliKey | OKP Public Key | |

<!-- INCLUDE(examples/jwk_new_example_test.go) -->
```go
package examples

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/rsa"
  "fmt"

  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_New() {
  // First, THIS IS THE WRONG WAY TO USE jwk.New().
  //
  // Assume that the file contains a JWK in JSON format
  //
  //  buf, _ := os.ReadFile(file)
  //  key, _ := json.New(buf)
  //
  // This is not right, because the jwk.New() function determines
  // the type of `jwk.Key` to create based on the TYPE of the argument.
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
  {
    raw := []byte("Lorem Ipsum")
    key, err := jwk.New(raw)
    if err != nil {
      fmt.Printf("failed to create symmetric key: %s\n", err)
      return
    }
    if _, ok := key.(jwk.SymmetricKey); !ok {
      fmt.Printf("expected jwk.SymmetricKey, got %T\n", key)
      return
    }
  }

  // *rsa.PrivateKey -> jwk.RSAPrivateKey
  // *rsa.PublicKey  -> jwk.RSAPublicKey
  {
    raw, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
      fmt.Printf("failed to generate new RSA privatre key: %s\n", err)
      return
    }

    key, err := jwk.New(raw)
    if err != nil {
      fmt.Printf("failed to create symmetric key: %s\n", err)
      return
    }
    if _, ok := key.(jwk.RSAPrivateKey); !ok {
      fmt.Printf("expected jwk.SymmetricKey, got %T\n", key)
      return
    }
    // PublicKey is omitted for brevity
  }

  // *ecdsa.PrivateKey -> jwk.ECDSAPrivateKey
  // *ecdsa.PublicKey  -> jwk.ECDSAPublicKey
  {
    raw, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    if err != nil {
      fmt.Printf("failed to generate new ECDSA privatre key: %s\n", err)
      return
    }

    key, err := jwk.New(raw)
    if err != nil {
      fmt.Printf("failed to create symmetric key: %s\n", err)
      return
    }
    if _, ok := key.(jwk.ECDSAPrivateKey); !ok {
      fmt.Printf("expected jwk.SymmetricKey, got %T\n", key)
      return
    }
    // PublicKey is omitted for brevity
  }

  // OUTPUT:
}
```
source: [examples/jwk_new_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwk_new_example_test.go)
<!-- END INCLUDE -->

## Construct a specific key type from scratch

Each of Symmetric, RSA, ECDSA, OKP key types have corresponding constructors to create an empty instance.
These keys are completely empty, so if you tried using them without initialization, it will not work.

```go
key := jwk.NewSymmetricKey()
key := jwk.NewECDSAPrivateKey()
key := jwk.NewECDSAPublicKey()
key := jwk.NewRSAPrivateKey()
key := jwk.NewRSAPublicKey()
key := jwk.NewOKPPrivateKey()
key := jwk.NewOKPPublicKey()
```

For advanced users: Once you obtain these "empty" objects, you *can* use `json.Unmarshal()` to parse the JWK.

```
// OK
key := jwk.NewRSAPrivateKey()
if err := json.Unmarshal(src, key); err != nil {
  return errors.New(`failed to unmarshal RSA key`)
}

// NOT OK
var key jwk.Key // we can't do this because we don't know where to store the data
if err := json.Unmarshal(src, &key); err !+ nil {
  ...
}
```

## Construct a specific key type from a raw key

[`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#New) already does this, but if for some reason you would like to initialize an already existing [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Key), you can use the [`jwk.FromRaw()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#FromRaw) method.

```go
privkey, err := rsa.GenerateKey(...)

key := jwk.NewRSAPrivateKey()
err := key.FromRaw(privkey)
```

## Setting values to fields

Using [`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#New) or [`jwk.FromRaw()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#FromRaw) allows you to populate the fields that are required to do perform the computations, but there are other fields that you may want to populate in a key. These fields can all be set using the [`jwk.Set()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Set) method.

The [`jwk.Set()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Set) method takes the name of the key, and a value to be associated with it. Some predefined keys have specific types (in which type checks are enforced), and others not.

[`jwk.Set()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Set) may not alter the Key Type (`kty`) field of a key.

the `jwk` package defines field key names for predefined keys as constants so you won't ever have to bang your head againt the wall after finding out that you have a typo.

```go
key.Set(jwk.KeyIDKey, `my-awesome-key`)
key.Set(`my-custom-field`, `unbelievable-value`)
```
# Fetching JWK Sets

## Fetching a JWK Set once

To fetch a JWK Set once, use `jwk.Fetch()`.

```go
set, err := jwk.Fetch(ctx, url, options...)
```

## Auto-refreshing remote keys

Sometimes you need to fetch a remote JWK, and use it mltiple times in a long-running process.
For example, you may act as an itermediary to some other service, and you may need to verify incoming JWT tokens against the tokens in said other service.

Normally, you should be able to simply fetch the JWK using [`jwk.Fetch()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Fetch),
but keys are usually routinely expired and rotated due to security reasons.
In such cases you would need to refetch the JWK periodically, which is a pain.

`github.com/lestrrat-go/jwx/v2/jwk` provides the [`jwk.AutoRefresh`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#AutoRefresh) tool to do this for you.

<!-- INCLUDE(examples/jwk_auto_refresh_example_test.go) -->
```go
package examples

import (
  "context"
  "fmt"
  "time"

  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_AutoRefresh() {
  ctx, cancel := context.WithCancel(context.Background())

  const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

  // First, set up the `jwk.AutoRefresh` object. You need to pass it a
  // `context.Context` object to control the lifecycle of the background fetching goroutine.
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
    // The returned `keyset` will always be "reasonably" new. It is important that
    // you always call `ar.Fetch()` before using the `keyset` as this is where the refreshing occurs.
    //
    // By "reasonably" we mean that we cannot guarantee that the keys will be refreshed
    // immediately after it has been rotated in the remote source. But it should be close\
    // enough, and should you need to forcefully refresh the token using the `(jwk.AutoRefresh).Refresh()` method.
    //
    // If re-fetching the keyset fails, a cached version will be returned from the previous successful
    // fetch upon calling `(jwk.AutoRefresh).Fetch()`.

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
source: [examples/jwk_auto_refresh_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwk_auto_refresh_example_test.go)
<!-- END INCLUDE -->

## Using Whitelists

If you are fetching JWK Sets from a possibly untrusted source such as the URL in the`"jku"` field of a JWS message,
you may have to perform some sort of whitelist checking. You can provide a `jwk.Whitelist` object to either
`jwk.Fetch()` or `(*jwk.AutoRefresh).Configure()` methods to specify the use of a whitelist.

Currently the package provides `jwk.MapWhitelist` and `jwk.RegexpWhitelist` types for simpler cases,
as well as `jwk.InsecureWhitelist` for when you explicitly want to allo all URLs.
If you would like to implement something more complex, you can provide a function via `jwk.WhitelistFunc` or implement you own type of `jwk.Whitelist`.

<!-- INCLUDE(examples/jwk_whitelist_example_test.go) -->
```go
package examples_test

import (
  "context"
  "encoding/json"
  "fmt"
  "net/http"
  "net/http/httptest"
  "os"
  "regexp"

  "github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_Whitelist() {
  srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, `{
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
    }`)
  }))
  defer srv.Close()

  testcases := []struct {
    Whitelist jwk.Whitelist
    Error     bool
  }{
    // The first two whitelists are meant to prevent access to any other
    // URLs other than www.google.com
    {
      Whitelist: jwk.NewMapWhitelist().Add(`https://www.googleapis.com/oauth2/v3/certs`),
      Error:     true,
    },
    {
      Whitelist: jwk.NewRegexpWhitelist().Add(regexp.MustCompile(`^https://www\.googleapis\.com/`)),
      Error:     true,
    },
    // Thist whitelist allows anything
    {
      Whitelist: jwk.InsecureWhitelist{},
    },
  }

  for _, tc := range testcases {
    set, err := jwk.Fetch(
      context.Background(),
      srv.URL,
      // This is necessary because httptest.Server is using a custom certificate
      jwk.WithHTTPClient(srv.Client()),
      // Pass the whitelist!
      jwk.WithFetchWhitelist(tc.Whitelist),
    )
    if tc.Error {
      if err == nil {
        fmt.Printf("expected fetch to fail, but got no error\n")
        return
      }
    } else {
      if err != nil {
        fmt.Printf("failed to fetch JWKS: %s\n", err)
        return
      }
      json.NewEncoder(os.Stdout).Encode(set)
    }
  }

  // OUTPUT:
  // {"keys":[{"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}]}
}
```
source: [examples/jwk_whitelist_example_test.go](https://github.com/lestrrat-go/jwx/blob/v2/examples/jwk_whitelist_example_test.go)
<!-- END INCLUDE -->

# Converting a jwk.Key to a raw key

As discussed in [Terminology](#terminology), this package calls the "original" keys (e.g. `rsa.PublicKey`, `ecdsa.PrivateKey`, etc) as "raw" keys. To obtain a raw key from a  [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Key) object, use the [`Raw()`](https://github.com/github.com/lestrrat-go/jwx/v2/jwk#Raw) method.

```go
key, _ := jwk.ParseKey(src)

var raw interface{}
if err := key.Raw(&raw); err != nil {
  ...
}
```

In the above example, `raw` contains whatever the [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#Key) represents.
If `key` represents an RSA key, it will contain either a `rsa.PublicKey` or `rsa.PrivateKey`. If it represents an ECDSA key, an `ecdsa.PublicKey`, or `ecdsa.PrivateKey`, etc.

If the only operation that you are performing is to grab the raw key out of a JSON JWK, use [`jwk.ParseRawKey`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk#ParseRawKey)

```go
var raw interface{}
if err := jwk.ParseRawKey(src, &raw); err != nil {
  ...
}
```
