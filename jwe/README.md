# JWE [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx/v4/jwe.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwe)

Package jwe implements JWE as described in [RFC 7516](https://tools.ietf.org/html/rfc7516). See [Working with JWE](../docs/03-jwe.md) for how-to style documentation and examples.

## Supported key encryption algorithms

| Algorithm                                | Constant in [jwa](../jwa) | Note |
|:-----------------------------------------|:--------------------------|:-----|
| RSA-PKCS1v1.5                            | jwa.RSA1_5                | Legacy interop only; prefer RSA-OAEP for new code |
| RSA-OAEP-SHA1                            | jwa.RSA_OAEP              |      |
| RSA-OAEP-SHA256                          | jwa.RSA_OAEP_256          |      |
| AES key wrap (128/192/256)               | jwa.A128KW / A192KW / A256KW |   |
| Direct encryption                        | jwa.DIRECT                | Single-recipient only |
| ECDH-ES                                  | jwa.ECDH_ES               | Single-recipient only |
| ECDH-ES + AES key wrap (128/192/256)     | jwa.ECDH_ES_A128KW / A192KW / A256KW | |
| AES-GCM key wrap (128/192/256)           | jwa.A128GCMKW / A192GCMKW / A256GCMKW | |
| PBES2 + HMAC-SHA + AES key wrap          | jwa.PBES2_HS256_A128KW / HS384_A192KW / HS512_A256KW | |
| HPKE (multiple modes)                    | jwa.HPKE_0_KE .. HPKE_7_KE | Single-recipient only |
| ML-KEM-768                               | mlkem.MLKEM768() / MLKEM768A192KW() | Companion module [`github.com/jwx-go/mlkem`](https://github.com/jwx-go/mlkem) (draft-ietf-jose-pqc-kem) |
| ML-KEM-1024                              | mlkem.MLKEM1024() / MLKEM1024A256KW() | Companion module [`github.com/jwx-go/mlkem`](https://github.com/jwx-go/mlkem) (draft-ietf-jose-pqc-kem) |

## Supported content encryption algorithms

| Algorithm                   | Constant in [jwa](../jwa) | Required CEK length |
|:----------------------------|:--------------------------|:--------------------|
| AES-CBC + HMAC-SHA256 (128) | jwa.A128CBC_HS256         | 32 bytes            |
| AES-CBC + HMAC-SHA384 (192) | jwa.A192CBC_HS384         | 48 bytes            |
| AES-CBC + HMAC-SHA512 (256) | jwa.A256CBC_HS512         | 64 bytes            |
| AES-GCM (128)               | jwa.A128GCM               | 16 bytes            |
| AES-GCM (192)               | jwa.A192GCM               | 24 bytes            |
| AES-GCM (256)               | jwa.A256GCM               | 32 bytes            |
