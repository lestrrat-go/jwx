<!-- Agent-consumed file. Keep terse, unambiguous, machine-parseable. -->

# Internal Dependency Graph

Arrows show import direction: `A → B` means A imports B.

## Layer Diagram

```
Application Layer
  cmd/jwx → jwt, jws, jwe, jwk, jwa

Composition Layer
  jwt → jws, jwe, jwk, jwa, transform, internal/{json}
  jwt/openid → jwt, internal/{json,tokens,pool}

Processing Layer
  jws → jwa, jwk, cert, internal/{base64,json,pool,tokens}
       → jws/jwsbb, jws/internal/jwsbb
       → crypto/mldsa (go1.27 only, via mldsa.go)
  jwe → jwa, jwk, cert, transform, internal/{base64,json,pool,tokens}
       → jwe/internal/{aescbc,cipher,concatkdf,content_crypt,keygen}
       → jwe/jwebb

Core Layer
  jwk → jwa, cert, transform, internal/{base64,json,ecutil}
       → jwk/ecdsa, jwk/jwkbb
       → crypto/mldsa (go1.27 only, via mldsa.go)
  jwx (root) → internal/json

Leaf Packages (no internal deps)
  jwa → internal/tokens
  cert → internal/{base64,tokens}
  transform → (stdlib only)
  internal/{base64,json,ecutil,pool,tokens}
```

## Package Import Summary

| Package | Imports from jwx |
|---------|-----------------|
| `jwa` | internal/tokens |
| `cert` | internal/{base64,tokens} |
| `transform` | (none — stdlib only) |
| `jwk` | jwa, cert, transform |
| `jwk/ecdsa` | jwa |
| `jwk/jwkbb` | (no internal jwx deps; uses valyala/fastjson) |
| `jws` | jwa, jwk, cert |
| `jwe` | jwa, jwk, cert, transform |
| `jwt` | jwa, jws, jwe, jwk, transform |
| `jwt/openid` | jwt |

## Key External Dependencies

| Dependency | Used by | Purpose |
|------------|---------|---------|
| `lestrrat-go/dsig` | jws, jws/jwsbb | Digital signature primitives (HMAC, RSA, ECDSA, EdDSA, and ML-DSA on Go 1.27). v1.4.0 or later is required, since it owns the ML-DSA algorithms and the `dsig.MLDSAFamily` family. |
| `lestrrat-go/option/v3` | all packages | Functional options pattern |
| `valyala/fastjson` | jws/internal/jwsbb, jwk/jwkbb | Fast JSON header / object peek |
| `golang.org/x/crypto` | jwe | Extended crypto (PBKDF2, etc.) |
