<!-- Agent-consumed file. Keep terse, unambiguous, machine-parseable. -->

# Internal Dependency Graph

Arrows show import direction: `A → B` means A imports B.

## Layer Diagram

```
Application Layer
  cmd/jwx → jwt, jws, jwe, jwk, jwa
  examples → jwt, jws, jwe, jwk, jwa

Composition Layer
  jwt → jws, jwe, jwk, jwa, transform, internal/{json}
  jwt/openid → jwt, internal/{json,tokens,pool}

Processing Layer
  jws → jwa, jwk, cert, internal/{base64,json,jwxio,pool,tokens}
       → jws/jwsbb
  jwe → jwa, jwk, cert, transform, internal/{base64,json,pool,tokens}
       → jwe/internal/{aescbc,cipher,concatkdf,content_crypt,keygen}

Core Layer
  jwk → jwa, cert, transform, internal/{base64,json,ecutil}
  jwx (root) → internal/json

Leaf Packages (no internal deps)
  jwa → internal/tokens
  cert → (stdlib only)
  transform → (stdlib only)
  internal/{base64,json,ecutil,pool,tokens,jwxio}
```

## Package Import Summary

| Package | Imports from jwx |
|---------|-----------------|
| `jwa` | internal/tokens |
| `cert` | (none) |
| `transform` | (none) |
| `jwk` | jwa, cert, transform |
| `jws` | jwa, jwk, cert |
| `jwe` | jwa, jwk, cert, transform |
| `jwt` | jwa, jws, jwe, jwk, transform |
| `jwt/openid` | jwt |

## Key External Dependencies

| Dependency | Used by | Purpose |
|------------|---------|---------|
| `lestrrat-go/httprc/v3` | jwk | HTTP resource caching for JWKS |
| `lestrrat-go/blackmagic` | jwk, jws, jwe | Type reflection/assertion |
| `lestrrat-go/option/v2` | all packages | Functional options pattern |
| `goccy/go-json` | internal/json | Optional fast JSON (build tag) |
| `segmentio/asm` | internal/base64 | Optional fast base64 (build tag) |
| `decred/secp256k1` | jwa, jwk, jws | ES256K support (build tag) |
| `valyala/fastjson` | jwk | Fast JSON parsing for key probing |
| `golang.org/x/crypto` | jwe | Extended crypto (PBKDF2, etc.) |
