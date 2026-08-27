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
  jws → jwa, jwk, cert, internal/{base64,json,pool,tokens}
       → jws/jwsbb, jws/internal/keyalg, jws/internal/jwsbb
  jwe → jwa, jwk, cert, transform, internal/{base64,json,pool,tokens}
       → jwe/internal/{aescbc,cipher,concatkdf,content_crypt,keygen}
       → jwe/jwebb

Core Layer
  jwk → jwa, cert, transform, internal/{base64,json,ecutil}
       → jwk/ecdsa, jwk/jwkbb
  jwx (root) → internal/json

Leaf Packages (no internal deps)
  jwa → internal/tokens
  cert → internal/{base64,tokens}
  transform → (stdlib + blackmagic)
  internal/{base64,json,ecutil,pool,tokens}
```

## Package Import Summary

| Package | Imports from jwx |
|---------|-----------------|
| `jwa` | internal/tokens |
| `cert` | internal/{base64,tokens} |
| `transform` | (none — external only: blackmagic) |
| `jwk` | jwa, cert, transform |
| `jwk/ecdsa` | jwa |
| `jwk/jwkbb` | (external only: blackmagic, valyala/fastjson) |
| `jws` | jwa, jwk, cert |
| `jws/internal/keyalg` | jwa, jwk |
| `jws/internal/jwsbb` | (external only: lestrrat-go/dsig) |
| `jwe` | jwa, jwk, cert, transform |
| `jwt` | jwa, jws, jwe, jwk, transform |
| `jwt/openid` | jwt |

## Key External Dependencies

| Dependency | Used by | Purpose |
|------------|---------|---------|
| `lestrrat-go/httprc/v3` | jwk | HTTP resource caching for JWKS |
| `lestrrat-go/blackmagic` | jwk, jws, jwe, transform | Type reflection/assertion |
| `lestrrat-go/option/v2` | all packages | Functional options pattern |
| `goccy/go-json` | internal/json | Optional fast JSON (build tag) |
| `segmentio/asm` | internal/base64 | Optional fast base64 (build tag) |
| `decred/secp256k1` | jwk (direct); jwa, jws (via build tag) | ES256K support (build tag) |
| `valyala/fastjson` | jws/jwsbb, jwk/jwkbb | Fast JSON header / object peek |
| `golang.org/x/crypto` | jwe | Extended crypto (PBKDF2, etc.) |
| `lestrrat-go/dsig` | jws, jws/jwsbb, jws/internal/jwsbb | Digital signature primitives (HMAC, RSA, ECDSA, EdDSA) |
| `lestrrat-go/dsig-secp256k1` | jws/jwsbb | ES256K/secp256k1 signature support (build tag) |
