<!-- Agent-consumed file. Keep terse, unambiguous, machine-parseable. -->

# Internal Dependency Graph

Arrows show import direction: `A → B` means A imports B.

## Layer Diagram

```
Application Layer
  cmd/jwx → jwt, jws, jwe, jwk, jwa

Composition Layer
  jwt → jwx, jws, jwe, jwk, jwa, jws/jwsbb, jwt/internal/types
      → internal/{base64,json,pool,tokens}
  jwt/openid → jwt, jwt/internal/types, internal/{json,tokens,pool}

Processing Layer
  jws → jwa, jwk, cert, internal/{base64,json,keyconv,pool,tokens}
       → jws/jwsbb, jws/internal/jwsbb, jws/internal/keyalg
       → crypto/mldsa (go1.27 only, via mldsa.go)
  jwe → jwa, jwk, cert, internal/{base64,json,keyconv,pool,tokens}
       → jwe/internal/{aescbc,content_crypt,keygen}
       → jwe/jwebb

Core Layer
  jwk → jwa, cert, internal/{base64,json,ecutil,pool}
       → jwk/ecdsa, jwk/internal/registry, jwk/jwkbb
       → crypto/mldsa (go1.27 only, via mldsa.go)
  jwx (root) → internal/{base64,json,tokens}

Foundational Packages
  jwa → internal/tokens
  cert → internal/{base64,tokens}
  internal/json → internal/{base64,tokens}
  internal/{base64,ecutil,pool,tokens}
```

## Package Import Summary

| Package | Imports from jwx |
|---------|-----------------|
| `jwa` | internal/tokens |
| `cert` | internal/{base64,tokens} |
| `jwk` | jwa, cert |
| `jwk/ecdsa` | jwa |
| `jwk/jwkbb` | internal/json |
| `jws` | jwa, jwk, cert |
| `jws/internal/keyalg` | jwa, jwk |
| `jwe` | jwa, jwk, cert |
| `jwt` | jwx, jwa, jws, jwe, jwk, jws/jwsbb, jwt/internal/types |
| `jwt/openid` | jwt, jwt/internal/types |

## Key External Dependencies

| Dependency | Used by | Purpose |
|------------|---------|---------|
| `lestrrat-go/dsig` | jws, jws/jwsbb | Digital signature primitives (HMAC, RSA, ECDSA, EdDSA, and ML-DSA on Go 1.27). v1.4.0 or later is required, since it owns the ML-DSA algorithms and the `dsig.MLDSAFamily` family. |
| `lestrrat-go/option/v3` | all packages | Functional options pattern |
| `golang.org/x/crypto` | jwe | Extended crypto (PBKDF2, etc.) |
