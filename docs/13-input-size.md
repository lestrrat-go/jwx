# Input Size and Resource Limits

This document describes how `github.com/lestrrat-go/jwx/v4` thinks about
bounding resource use during parse and decrypt. The short version:

- **Raw input size is the caller's responsibility.** The library does
  not cap the number of bytes it reads from a `[]byte`, `string`, or
  `io.Reader` handed to `jwt.Parse*`, `jws.Parse*`, `jwe.Parse*`, or
  `jwe.Decrypt`.
- **Amplification and structural limits are the library's
  responsibility.** When the work the library performs can grow
  significantly larger than the input — decompression, PBKDF2
  iterations, recipient fan-out, intermediate buffers — the library
  enforces a cap that the caller cannot compute from the input size.

## Raw input: bound it at the source

If you are parsing bytes you already have in memory, you allocated
them and you know how big they are. If you are parsing from an
`io.Reader`, wrap it:

```go
// HTTP handler: cap the request body.
body := http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB
tok, err := jwt.ParseReader(body, jwt.WithKey(alg, key))
```

```go
// Generic Reader: io.LimitReader.
limited := io.LimitReader(src, 1<<20)
msg, err := jws.ParseReader(limited)
```

The library will read whatever you hand it. A `nil`-free read is
trusted; `io.LimitReader` / `http.MaxBytesReader` is what stops a
pathological producer from exhausting memory.

This matches what the Go standard library does in equivalent places.
`encoding/json.Decoder`, `crypto/x509.ParseCertificate`, and
`net/http` all trust the caller to bound input. Putting a cap inside
the library would be redundant with the caller's bound when there is
one, and wrong (either too permissive or too restrictive) when the
library guesses for the caller.

## Amplification and structural limits

These caps are inside the library because the caller cannot predict
the amplification from the input size alone.

### JWE: decompression (`zip: DEF`)

A 1 KiB compressed payload can inflate to gigabytes. `jwe.Decrypt`
aborts the inflate when the decompressed size exceeds
`jwe.WithMaxDecompressBufferSize` (default **10 MiB**).

```go
jwe.Settings(jwe.WithMaxDecompressBufferSize(32 << 20)) // 32 MiB globally
jwe.Decrypt(buf, jwe.WithKey(alg, key),
    jwe.WithMaxDecompressBufferSize(256 << 10)) // 256 KiB for this call
```

### JWE: number of recipients

A JSON-serialized JWE with many recipients multiplies per-recipient
key-unwrap work. `jwe.Decrypt` rejects messages with more than
`jwe.WithMaxRecipients` entries (default **100**).

### JWE: PBES2 iteration count

`PBES2-HS256+A128KW` and friends run PBKDF2 over an iteration count
that the producer chose. `jwe.Decrypt` rejects counts outside
`[jwe.WithMinPBES2Count, jwe.WithMaxPBES2Count]` (defaults **1,000**
and **1,000,000** — 1M covers OWASP 2023's 600k HS256 baseline with
headroom). Note that `jwe.Decrypt` only reaches the PBES2 path when
the caller explicitly configures a password key via `jwe.WithKey`.

### JWE: AES-CBC intermediate buffer

AES-CBC decryption allocates an intermediate buffer bounded by
`jwe.WithCBCBufferSize` (default **256 MiB**).

### JWT: nested depth

Nested JWTs (a JWS whose payload is a JWT) are accepted up to a fixed
depth of **2**. The library will not recursively unwrap beyond that.

### JWS: number of signatures (JSON serialization)

A JSON-serialized JWS can carry multiple signatures. `jws.Parse`
rejects messages with more than `jws.WithMaxSignatures` entries
(default **100**).

### JWK: number of keys in a set

A JWKS can carry many keys; each entry triggers a probe + unmarshal
+ validation when parsed. `jwk.Parse` rejects inputs with more than
`jwk.WithMaxKeys` entries (default **1000**). The cap applies to
both the JSON `"keys"` array and the PEM block stream accepted via
`jwk.WithX509(true)`.

```go
jwk.Settings(jwk.WithMaxKeys(500))                    // globally
jwk.Parse(buf, jwk.WithMaxKeys(100))                  // per call
```

## What this means for reviewers

If an audit or review flags "unbounded `io.ReadAll`", "no max input
size", or "DoS via large input" on `jwt.Parse*`, `jws.Parse*`,
`jwe.Parse*`, `jwe.Decrypt`, or `jws/jwsbb.SplitCompactReader`: that
is the documented stance, not an oversight. The caller is expected
to bound the input before it reaches the library. This document
exists so that stance does not need to be re-litigated per review.

Flag any of the following instead, which are real gaps:

- An amplification ratio (decompression, recipient fan-out, PBKDF2
  cost, intermediate buffer) that is uncapped inside the library.
- An option listed above whose default is inappropriate for the
  current threat model and cannot be lowered through `Settings()` or
  a per-call override.
- A code path that bypasses one of the caps above.
