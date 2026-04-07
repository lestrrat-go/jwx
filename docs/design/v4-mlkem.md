# ML-KEM Support for JWE

**Status**: Draft (revised after adversarial review)
**Branch**: develop-v4
**Spec reference**: [draft-ietf-jose-pqc-kem-05](https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/)

## Overview

Add post-quantum key encapsulation (ML-KEM) to JWE, using Go's `crypto/mlkem` stdlib package (available since Go 1.24; v4 targets Go 1.26). Follows [draft-ietf-jose-pqc-kem](https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/) for algorithm identifiers, key format, and encapsulation flow.

ML-KEM is fundamentally different from existing JWE key encryption: it is a **KEM** (Key Encapsulation Mechanism), not key wrapping or key transport. The sender calls `Encapsulate()` on the recipient's public key to get a (shared secret, ciphertext) pair. The recipient calls `Decapsulate(ciphertext)` to recover the shared secret. The CEK is either the shared secret directly (direct mode) or wrapped with it (key-wrap mode).

## Spec: Algorithm Identifiers

Per draft-ietf-jose-pqc-kem, the `alg` header values are:

| `alg` value | Mode | KEM parameter set | Key-wrap |
|---|---|---|---|
| `ML-KEM-768` | Direct key agreement | ML-KEM-768 | None (shared secret = CEK) |
| `ML-KEM-1024` | Direct key agreement | ML-KEM-1024 | None (shared secret = CEK) |
| `ML-KEM-768+A192KW` | Key agreement + wrap | ML-KEM-768 | AES-192 KeyWrap |
| `ML-KEM-1024+A256KW` | Key agreement + wrap | ML-KEM-1024 | AES-256 KeyWrap |

> **Decision: Skip ML-KEM-512.** NIST recommends ML-KEM-768 as the baseline, and the Go stdlib does not provide ML-KEM-512. The draft also registers ML-KEM-512 variants, but we omit them.

## Spec: JWK Key Type

Per the draft, ML-KEM keys use the `AKP` (Algorithm Key Pair) key type, defined in
[draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium):

- `"kty": "AKP"`
- `"pub"`: base64url-encoded encapsulation key (public key)
- `"priv"`: base64url-encoded private key seed
- `"alg"`: **mandatory** — one of `ML-KEM-768`, `ML-KEM-1024`, `ML-KEM-768+A192KW`, `ML-KEM-1024+A256KW`

AKP field semantics are algorithm-specific: "The parameters for public and private
information classes contain byte strings in a format specified by the `alg` value"
([draft-ietf-cose-dilithium, Section 3](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium)).

### Private Key Seed Size: 32-byte `priv` + 32-byte `z` Extension

> **This is a critical design decision. Read this section carefully.**

#### The problem

[draft-ietf-jose-pqc-kem-05, Section 10](https://datatracker.ietf.org/doc/html/draft-ietf-jose-pqc-kem-05)
mandates:

> "this specification mandates that the 'priv' parameter MUST contain the **32-byte seed**
> used to generate the ML-KEM key pair"

However, [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) defines the ML-KEM seed as
**64 bytes** in the `d || z` form, where:

- **`d`** (32 bytes): generates the public key matrix and secret vectors
  (Algorithm 16: `ML-KEM.KeyGen_internal(d, z)`)
- **`z`** (32 bytes): used solely for **implicit rejection** during decapsulation
  (Algorithm 18: `ML-KEM.Decaps_internal`) — when a tampered ciphertext is detected,
  the function returns `SHAKE256(z || c)` instead of the real shared secret, making
  failure indistinguishable from success to prevent timing side-channels

Go's `crypto/mlkem` API requires the full 64-byte seed:

```go
// NewDecapsulationKey768 expands a decapsulation key from a 64-byte seed
// in the "d || z" form. The seed must be uniformly random.
func NewDecapsulationKey768(seed []byte) (*DecapsulationKey768, error)
```

There is no Go API to construct a `DecapsulationKey` from 32 bytes alone.

Source: [Go `crypto/mlkem` documentation](https://pkg.go.dev/crypto/mlkem),
[Go internal FIPS 140 ML-KEM implementation](https://tip.golang.org/src/crypto/internal/fips140/mlkem/mlkem768.go).

#### Why the draft likely has a bug

The `AKP` key type was designed alongside
[ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final), where the private key
seed is genuinely 32 bytes — a single value `ξ` that fully determines the entire key pair.
The [draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium)
correctly specifies 32 bytes for ML-DSA's `priv`.

ML-KEM is different: its seed is `(d, z)` = 64 bytes. The JOSE draft appears to have
carried over the 32-byte assumption from ML-DSA without accounting for this difference.

Evidence:
- FIPS 203 Algorithm 16 (`ML-KEM.KeyGen_internal`) takes **two** 32-byte inputs `(d, z)`.
- FIPS 203 Algorithm 19 (`ML-KEM.KeyGen`) generates **both** `d` and `z` randomly.
- Go's `mlkem.SeedSize = 64`, and `DecapsulationKey.Bytes()` returns 64 bytes.
- [OpenSSL's ML-KEM design](https://github.com/openssl/openssl/blob/master/doc/designs/ML-KEM.md)
  also uses the 64-byte `(d, z)` pair as the seed form.

As of April 2026, **no known JOSE/COSE library has implemented draft-ietf-jose-pqc-kem**,
so there is no interop baseline to check against.

#### Our decision

**Store 32 bytes in `"priv"` (the `d` component) per the draft, and add a private
extension field `"z"` (32 bytes) for the implicit rejection seed.**

Behavior:

| Scenario | `priv` | `z` | On import |
|---|---|---|---|
| Full key (our export) | 32 bytes (`d`) | 32 bytes (`z`) | Reconstruct `DecapsulationKey` from `d \|\| z` |
| Spec-only key (other impl) | 32 bytes (`d`) | absent | Generate fresh random `z`, reconstruct from `d \|\| z` |
| Public key only | absent | absent | Construct `EncapsulationKey` from `pub` |

Rationale:

1. **Spec compliance**: `"priv"` contains exactly 32 bytes, satisfying the draft's MUST.
2. **Lossless round-trip**: When `"z"` is present, the full key is preserved across
   serialization. Keys exported by jwx can be re-imported without loss.
3. **Interop**: JWKs from other implementations (without `"z"`) are accepted. A fresh
   random `z` is equally valid for implicit rejection — it just changes which value
   gets returned on invalid ciphertext, not the behavior on valid ciphertext.
4. **Security**: Implicit rejection is preserved either way. `z` does not affect the
   encapsulation key or valid decapsulation — it only determines the fake shared secret
   returned on tampered ciphertexts.
5. **Future-proof**: If the draft is corrected to 64 bytes in a future revision, we
   can migrate by concatenating `priv || z` into a single 64-byte `priv` field.

The `"z"` field:
- JSON key: `"z"`
- Value: base64url-encoded 32 bytes
- MUST NOT be present without `"priv"`
- SHOULD be included when exporting private keys
- If absent on import, a fresh 32-byte random value is generated via `crypto/rand`

## Spec: JWE Header Parameter

The KEM ciphertext is carried in a new per-recipient header field:

- `"ek"`: base64url-encoded KEM ciphertext

This is analogous to `"epk"` for ECDH-ES, but carries the KEM ciphertext instead of an ephemeral public key.

In **direct** mode (`ML-KEM-768`, `ML-KEM-1024`), the JWE Encrypted Key MUST be absent.
In **key-wrap** mode (`ML-KEM-768+A192KW`, `ML-KEM-1024+A256KW`), the JWE Encrypted Key
contains the wrapped CEK.

## Spec: CEK Derivation (KDF)

The draft specifies a KMAC256-based KDF per
[NIST SP 800-108r1-upd1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf)
with context fields from
[NIST SP 800-56Ar3, Section 5.8.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf):

```
SS = KMAC256(K, X, L, S)
```

Where:
- **K** (key) = SS' (raw KEM shared secret, 32 bytes)
- **X** (data) = AlgorithmID || SuppPubInfo || SuppPrivInfo
  - `AlgorithmID`: the `alg` string for key-wrap mode, or the `enc` string for direct mode
    (same convention as ECDH-ES in the existing `concatkdf` implementation)
  - `SuppPubInfo`: 4-byte big-endian key data length in bits
  - `SuppPrivInfo`: empty
- **L** (output length) = key size in bits matching the AEAD or key-wrap algorithm
- **S** (customization) = `""` (empty string)

This is structurally analogous to the Concat KDF used by ECDH-ES (already implemented in
`jwe/internal/concatkdf/`), with KMAC256 replacing SHA-256 as the PRF.

### KMAC256 implementation

KMAC256 is defined in [NIST SP 800-185, Section 4](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf).
It is built on cSHAKE256:

```
KMAC256(K, X, L, S) = cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L), L, "KMAC", S)
```

Go's `golang.org/x/crypto/sha3` provides `NewCShake256(N, S)` but **not** KMAC256 directly.
We must implement the KMAC256 construction (~30 lines) using `bytepad`, `encode_string`,
and `right_encode` primitives from SP 800-185 on top of `sha3.NewCShake256`.

The project already depends on `golang.org/x/crypto` (v0.49.0 in v4's go.mod).

## Go `crypto/mlkem` API

```go
// ML-KEM-768
func GenerateKey768() (*DecapsulationKey768, error)
func NewDecapsulationKey768(seed []byte) (*DecapsulationKey768, error)  // 64-byte seed
func NewEncapsulationKey768(key []byte) (*EncapsulationKey768, error)   // 1184 bytes

func (dk *DecapsulationKey768) Bytes() []byte            // 64-byte seed (d || z)
func (dk *DecapsulationKey768) EncapsulationKey() *EncapsulationKey768
func (dk *DecapsulationKey768) Decapsulate(ct []byte) ([]byte, error)

func (ek *EncapsulationKey768) Bytes() []byte             // 1184 bytes
func (ek *EncapsulationKey768) Encapsulate() (sharedKey, ciphertext []byte)

// ML-KEM-1024 — same shape, larger sizes
func GenerateKey1024() (*DecapsulationKey1024, error)
// ... analogous methods
```

Constants: `SharedKeySize = 32`, `SeedSize = 64`, `CiphertextSize768 = 1088`,
`EncapsulationKeySize768 = 1184`, `CiphertextSize1024 = 1568`,
`EncapsulationKeySize1024 = 1568`.

Source: [crypto/mlkem package documentation](https://pkg.go.dev/crypto/mlkem).

---

## Implementation Plan

### Task 1: Add algorithm identifiers to `jwa`

**Files touched:**
- `internal/tokens/jwe_tokens.go` — add string constants
- `tools/cmd/genjwa/objects.yml` — add `KeyEncryptionAlgorithm` entries

Add to `internal/tokens/jwe_tokens.go`:
```go
// ML-KEM algorithms
ML_KEM_768          = "ML-KEM-768"
ML_KEM_1024         = "ML-KEM-1024"
ML_KEM_768_A192KW   = "ML-KEM-768+A192KW"
ML_KEM_1024_A256KW  = "ML-KEM-1024+A256KW"
```

Add to `tools/cmd/genjwa/objects.yml` under `KeyEncryptionAlgorithm.elements`:
```yaml
- name: ML_KEM_768
  value: ML-KEM-768
  token_reference: tokens.ML_KEM_768
  returnval_comment: ML-KEM-768 direct key agreement algorithm
- name: ML_KEM_1024
  value: ML-KEM-1024
  token_reference: tokens.ML_KEM_1024
  returnval_comment: ML-KEM-1024 direct key agreement algorithm
- name: ML_KEM_768_A192KW
  value: ML-KEM-768+A192KW
  token_reference: tokens.ML_KEM_768_A192KW
  returnval_comment: ML-KEM-768 + AES key wrap (192) key agreement algorithm
- name: ML_KEM_1024_A256KW
  value: ML-KEM-1024+A256KW
  token_reference: tokens.ML_KEM_1024_A256KW
  returnval_comment: ML-KEM-1024 + AES key wrap (256) key agreement algorithm
```

Then run `make generate-jwa`.

### Task 2: Add `"AKP"` key type and ML-KEM JWK key representation to `jwk`

**Files touched:**
- `tools/cmd/genjwa/objects.yml` — add `AKP` to `KeyType`
- `tools/cmd/genjwk/objects.yml` — add `AKP` key type with fields

Add to `KeyType` elements in genjwa `objects.yml`:
```yaml
- name: AKP
  value: AKP
  comment: Algorithm Key Pair (post-quantum KEM keys)
```

Add to `key_types` in genjwk `objects.yml`:
```yaml
- filename: akp_gen.go
  prefix: AKP
  key_type: jwa.AKP()
  objects:
    - name: publicKey
      raw_key_type: "any"
      fields:
        - name: pub
          type: "[]byte"
          required: true
        - name: alg
          type: jwa.KeyAlgorithm
          required: true
    - name: privateKey
      raw_key_type: "any"
      fields:
        - name: pub
          type: "[]byte"
          required: true
        - name: priv
          type: "[]byte"
          required: true
        - name: z
          type: "[]byte"
          comment: |
            ML-KEM implicit rejection seed. See "Private Key Seed Size"
            in docs/design/v4-mlkem.md for rationale.
        - name: alg
          type: jwa.KeyAlgorithm
          required: true
```

Then run `make generate-jwk` and `make generate-jwa`.

**Import/Export handlers** (hand-written, not generated) in `jwk/akp.go`:

Import dispatch follows the OKP pattern (`jwk/okp.go`):
- Register typed importers via `RegisterKeyImporter` for `*mlkem.EncapsulationKey768`,
  `*mlkem.DecapsulationKey768`, `*mlkem.EncapsulationKey1024`, `*mlkem.DecapsulationKey1024`
- The `Import()` method type-switches on the raw key to set `pub`, `priv`, `z`, and `alg`
- For `*mlkem.DecapsulationKey768`: `seed := dk.Bytes()` → `priv = seed[:32]` (`d`),
  `z = seed[32:]` (`z`), `pub = dk.EncapsulationKey().Bytes()`
- For `*mlkem.EncapsulationKey768`: `pub = ek.Bytes()`, no `priv`/`z`

Export dispatch follows the OKP `KeyKind` pattern:
- `KeyKind()` returns `"AKP:ML-KEM-768"` or `"AKP:ML-KEM-1024"` based on the `alg` field
  (analogous to OKP using `"OKP:Ed25519"` / `"OKP:X25519"` based on `crv`)
- Private key export: if `z` is present, `seed = priv || z` (64 bytes), call
  `mlkem.NewDecapsulationKey768(seed)`; if `z` is absent, generate 32 random bytes for `z`,
  then construct as above
- Public key export: call `mlkem.NewEncapsulationKey768(pub)`

### Task 3: Add `"ek"` header field to JWE headers

**Files touched:**
- `tools/cmd/genheaders/jwe-objects.yml` — add `ek` field

```yaml
- name: encapsulatedKey
  type: "[]byte"
  json: ek
```

Then run `make generate-jwe`.

### Task 4: Implement KMAC256 and KDF

**Files touched:**
- `jwe/internal/mlkemkdf/kmac.go` (new) — KMAC256 built on cSHAKE256
- `jwe/internal/mlkemkdf/kdf.go` (new) — KDF using KMAC256 with SP 800-56Ar3 context

KMAC256 construction per [NIST SP 800-185, Section 4](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf):
```
KMAC256(K, X, L, S) = cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L), L, "KMAC", S)
```

Requires implementing three SP 800-185 primitives:
- `encode_string(S)`: `left_encode(len(S)) || S`
- `bytepad(X, w)`: `left_encode(w) || X || zeros` (pad to multiple of `w`)
- `left_encode(x)` / `right_encode(x)`: big-endian variable-length integer encoding

KDF function:
```go
// DeriveKey derives a key from the KEM shared secret per draft-ietf-jose-pqc-kem.
// alg is the algorithm identifier (the "alg" value for key-wrap, or "enc" value for direct).
// ssLen is the desired output length in bytes.
func DeriveKey(sharedSecret []byte, alg string, ssLen int) ([]byte, error)
```

The KDF internally constructs:
- `AlgorithmID = alg` (UTF-8 string)
- `SuppPubInfo = big-endian uint32(ssLen * 8)` (key length in bits)
- `X = AlgorithmID || SuppPubInfo`
- Calls `KMAC256(K=sharedSecret, X=X, L=ssLen*8, S="")`

### Task 5: Implement ML-KEM key encrypt/decrypt in `jwe/jwebb`

**Files touched:**
- `jwe/jwebb/key_encryption.go` — add `IsMLKEM()` / `IsMLKEMDirect()` classifiers
- `jwe/jwebb/key_encrypt_mlkem.go` (new) — encrypt functions
- `jwe/jwebb/key_decrypt_mlkem.go` (new) — decrypt functions

**`key_encryption.go` addition:**
```go
func IsMLKEM(alg string) bool {
    switch alg {
    case tokens.ML_KEM_768, tokens.ML_KEM_1024,
         tokens.ML_KEM_768_A192KW, tokens.ML_KEM_1024_A256KW:
        return true
    default:
        return false
    }
}

func IsMLKEMDirect(alg string) bool {
    switch alg {
    case tokens.ML_KEM_768, tokens.ML_KEM_1024:
        return true
    default:
        return false
    }
}
```

**`key_encrypt_mlkem.go` — encryption side:**

```go
func KeyEncryptMLKEM(cek []byte, alg string, pubkey any) (keygen.ByteSource, error)
func KeyEncryptMLKEMKeyWrap(cek []byte, alg string, pubkey any) (keygen.ByteSource, error)
```

Flow:
1. Type-assert `pubkey` to `*mlkem.EncapsulationKey768` or `*mlkem.EncapsulationKey1024` based on `alg`
2. Call `pubkey.Encapsulate()` → `(sharedKey, ciphertext)`
3. Determine algorithm string for KDF: direct mode uses the `enc` (content encryption) alg,
   key-wrap mode uses the `alg` value itself
4. Call `mlkemkdf.DeriveKey(sharedKey, algorithmID, ssLen)` → `ss`
5. Direct mode: return `ByteWithEncapsulatedKey{ByteKey: ss, Ciphertext: ciphertext}`
6. Key-wrap mode: AES-KeyWrap `cek` with `ss`, return `ByteWithEncapsulatedKey{ByteKey: wrappedCEK, Ciphertext: ciphertext}`

**`key_decrypt_mlkem.go` — decryption side:**

```go
func KeyDecryptMLKEM(recipientKey []byte, cek []byte, alg string, privkey any, ciphertext []byte) ([]byte, error)
func KeyDecryptMLKEMKeyWrap(recipientKey []byte, enckey []byte, alg string, privkey any, ciphertext []byte) ([]byte, error)
```

### Task 6: Add `ByteWithEncapsulatedKey` to keygen

**Files touched:**
- `jwe/internal/keygen/interface.go` — add type
- `jwe/internal/keygen/keygen.go` — add `Populate` method

```go
type ByteWithEncapsulatedKey struct {
    ByteKey
    Ciphertext []byte
}

func (k ByteWithEncapsulatedKey) Populate(h Setter) error {
    return h.Set("ek", k.Ciphertext)
}
```

This uses the existing `populater` interface already checked in `recipientBuilder.Build()`.

### Task 7: Wire ML-KEM into the encrypt/decrypt dispatchers

**Files touched:**
- `jwe/encrypt.go` — add ML-KEM branch in `EncryptKey()`
- `jwe/decrypt.go` — add ML-KEM branch in `DecryptKey()`
- `jwe/jwe.go` — add ML-KEM direct algs to `recipientBuilder.Build()` and decrypt-side
  header extraction

**`encrypt.go` addition** (after ECDH-ES block, before RSA):
```go
if jwebb.IsMLKEM(keyalgStr) {
    keyToUse := e.rawKey
    if keyToUse == nil {
        keyToUse = e.pubkey
    }

    if jwebb.IsMLKEMDirect(keyalgStr) {
        return jwebb.KeyEncryptMLKEM(cek, keyalgStr, keyToUse)
    }
    return jwebb.KeyEncryptMLKEMKeyWrap(cek, keyalgStr, keyToUse)
}
```

**`decrypt.go` addition:**
```go
if jwebb.IsMLKEM(keyalgStr) {
    hdr := recipient.Headers()
    ek, ok := hdr.EncapsulatedKey()
    if !ok {
        return nil, fmt.Errorf("decrypt key: ML-KEM requires 'ek' header parameter")
    }

    if jwebb.IsMLKEMDirect(keyalgStr) {
        return jwebb.KeyDecryptMLKEM(recipientKey, cek, keyalgStr, d.privkey, ek)
    }
    return jwebb.KeyDecryptMLKEMKeyWrap(recipientKey, recipientKey, keyalgStr, d.privkey, ek)
}
```

**`jwe.go` `recipientBuilder.Build()` direct-mode fix** (line ~150):

Current code only checks `jwa.ECDH_ES()` and `jwa.DIRECT()` for direct mode (where
`rawCEK = enckey.Bytes()` and JWE Encrypted Key is absent). Must add ML-KEM direct algs:

```go
if b.alg == jwa.ECDH_ES() || b.alg == jwa.DIRECT() || b.alg == jwa.ML_KEM_768() || b.alg == jwa.ML_KEM_1024() {
    rawCEK = enckey.Bytes()
} else {
    if err := r.SetEncryptedKey(enckey.Bytes()); err != nil { ... }
}
```

**`jwe.go` decrypt-side header extraction** (after the ECDH-ES `epk` block at ~line 452):

Add a parallel block for ML-KEM algorithms that reads `"ek"` from the merged headers:
```go
case jwa.ML_KEM_768(), jwa.ML_KEM_1024(), jwa.ML_KEM_768_A192KW(), jwa.ML_KEM_1024_A256KW():
    // "ek" is read from headers inside DecryptKey — no additional
    // pre-extraction needed (unlike epk which must be converted from JWK).
    // The ek field is raw []byte, not a JWK, so no conversion step.
```

### Task 8: Algorithm-key validation

**Files touched:**
- Whatever file handles `WithKey()` validation (likely `jwe/jwe.go` or related)

Add ML-KEM key type checks:
- `ML-KEM-768` / `ML-KEM-768+A192KW` → accept `*mlkem.EncapsulationKey768` (encrypt) / `*mlkem.DecapsulationKey768` (decrypt)
- `ML-KEM-1024` / `ML-KEM-1024+A256KW` → accept `*mlkem.EncapsulationKey1024` (encrypt) / `*mlkem.DecapsulationKey1024` (decrypt)
- Also accept `jwk.Key` with `"kty": "AKP"` (resolved via `jwk.Export`)

---

## Design Decisions

### Why not HPKE-based approach?

There are two competing drafts: `draft-ietf-jose-pqc-kem` (direct KEM integration) and
`draft-reddy-cose-jose-pqc-hybrid-hpke` (ML-KEM via HPKE). We follow the first because:

1. It is the IETF JOSE WG adopted draft (working group item)
2. Direct KEM integration maps cleanly to the existing JWE encrypt/decrypt model
3. HPKE integration would require a larger architectural change and a separate design

HPKE-based PQ can be added later as a separate feature.

### Why skip ML-KEM-512?

- Go stdlib does not provide `crypto/mlkem` support for ML-KEM-512
- NIST recommends ML-KEM-768 as the baseline security level
- ML-KEM-512 is roughly equivalent to AES-128; ML-KEM-768 ≈ AES-192

### `"ek"` field vs reusing `"epk"`

The draft defines a new `"ek"` header parameter rather than reusing `"epk"`. This is correct because:
- `"epk"` carries a JWK (an ephemeral public key)
- `"ek"` carries raw ciphertext bytes (base64url-encoded)
- They are semantically different

### KMAC256 implementation

KMAC256 is specified in [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf).
Go does not have KMAC in stdlib or `golang.org/x/crypto`. The `golang.org/x/crypto/sha3`
package provides `NewCShake256(N, S)` which is the foundation, but KMAC256 adds its own
encoding layer (`bytepad`, `encode_string`, `right_encode`). We implement KMAC256 on top
of cSHAKE256 (~30 lines plus encoding helpers).

### No hybrid (PQ/T) in this phase

Hybrid algorithms (e.g., ML-KEM-768 + X25519) combine a traditional and PQ KEM.
The HPKE-based draft covers these. We defer hybrid support — pure ML-KEM is the
critical first step.

---

## Test Plan

1. **Round-trip tests**: Encrypt with each ML-KEM alg, decrypt, verify plaintext matches
2. **Cross-parameter tests**: Verify ML-KEM-768 keys cannot be used with ML-KEM-1024 alg (and vice versa)
3. **JWK serialization**: Marshal/unmarshal ML-KEM keys, verify `"kty": "AKP"`, `"pub"`, `"priv"`, `"z"` fields
4. **JWK without `z`**: Import a JWK with only `"priv"` (no `"z"`), verify decapsulation works (fresh `z` generated)
5. **JWK round-trip with `z`**: Export → import → export, verify `priv` and `z` are preserved
6. **Key import/export**: `jwk.Import(*mlkem.DecapsulationKey768)` → JWK → `jwk.Export[*mlkem.DecapsulationKey768]` → verify keys match
7. **Header `"ek"` field**: Verify KEM ciphertext appears in serialized JWE, round-trips correctly
8. **Direct mode**: Verify JWE Encrypted Key is absent in compact serialization for `ML-KEM-768` / `ML-KEM-1024`
9. **Key-wrap mode**: Verify JWE Encrypted Key is present for `ML-KEM-768+A192KW` / `ML-KEM-1024+A256KW`
10. **Algorithm-key mismatch**: Verify errors when wrong key type is provided
11. **KMAC256 test vectors**: Validate KMAC256 implementation against NIST SP 800-185 test vectors
12. **Interop vectors**: Once available from other implementations or the draft, add test vectors

## Task Ordering

```
Task 1 (jwa algorithms)
  └─► Task 2 (jwk key type + import/export) ──► Task 3 (jwe header "ek")
        └─► Task 4 (KMAC256 + KDF)
              └─► Task 5 (jwebb encrypt/decrypt) + Task 6 (keygen ByteSource)
                    └─► Task 7 (wire into dispatchers + direct-mode fix)
                          └─► Task 8 (algorithm-key validation)
```

Tasks 1-3 can proceed somewhat independently (they're all codegen). Tasks 4-6 are the
core crypto. Task 7 ties everything together. Task 8 validates constraints.

---

## References

| Document | URL | Relevance |
|---|---|---|
| draft-ietf-jose-pqc-kem-05 | https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/ | Primary spec for ML-KEM in JOSE |
| draft-ietf-cose-dilithium | https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium | Defines AKP key type |
| FIPS 203 (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final | ML-KEM standard (Algorithms 16, 18, 19) |
| FIPS 204 (ML-DSA) | https://csrc.nist.gov/pubs/fips/204/final | ML-DSA standard (AKP key type precedent) |
| NIST SP 800-185 | https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf | KMAC256 specification |
| NIST SP 800-108r1-upd1 | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf | KDF using KMAC |
| NIST SP 800-56Ar3 | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf | KDF context fields |
| Go crypto/mlkem | https://pkg.go.dev/crypto/mlkem | Go stdlib ML-KEM API |
| Go internal ML-KEM source | https://tip.golang.org/src/crypto/internal/fips140/mlkem/mlkem768.go | FIPS 203 implementation (d/z roles) |
| OpenSSL ML-KEM design | https://github.com/openssl/openssl/blob/master/doc/designs/ML-KEM.md | OpenSSL 64-byte seed precedent |
| draft-reddy-cose-jose-pqc-hybrid-hpke | https://datatracker.ietf.org/doc/draft-reddy-cose-jose-pqc-hybrid-hpke/ | HPKE-based PQ (deferred) |
