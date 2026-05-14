# v4 Design: Post-Quantum Composite Signatures

## Motivation

[draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/) defines six composite signature algorithms that pair ML-DSA (FIPS 204) with a traditional signature scheme (ECDSA P-256/P-384, Ed25519, or Ed448). Composite signing provides defense-in-depth during the PQ transition: both component signatures must verify, so a failure in either the post-quantum or the traditional component does not invalidate a signature on its own.

Although the JOSE draft is only at `-01`, its cryptographic construction is inherited from the far more mature [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) (X.509 bindings, currently at `-18`). The JOSE draft only adds the JWK shape, algorithm identifiers, and serialization bindings on top of the LAMPS construction.

## Scope

This change is additive: a new companion module under the jwx v4 ecosystem, no edits to the core library.

- New module: `github.com/jwx-go/compsig/v4`
- Repo layout follows the companion-module template (see `agents/docs/companions.md`)
- Local development clone lives at `.companions/repo/compsig/` (gitignored)
- Registered in `companions.yaml` alongside the other companion modules

The following composite algorithms are implemented in a single module:

| Algorithm | ML-DSA | Traditional | Pre-hash | Domain label |
|-----------|--------|-------------|----------|--------------|
| ML-DSA-44-ES256 | ML-DSA-44 | ECDSA P-256 | SHA-256 | `COMPSIG-MLDSA44-ECDSA-P256-SHA256` |
| ML-DSA-65-ES256 | ML-DSA-65 | ECDSA P-256 | SHA-512 | `COMPSIG-MLDSA65-ECDSA-P256-SHA512` |
| ML-DSA-87-ES384 | ML-DSA-87 | ECDSA P-384 | SHA-512 | `COMPSIG-MLDSA87-ECDSA-P384-SHA512` |
| ML-DSA-44-Ed25519 | ML-DSA-44 | Ed25519 | SHA-512 | `COMPSIG-MLDSA44-Ed25519-SHA512` |
| ML-DSA-65-Ed25519 | ML-DSA-65 | Ed25519 | SHA-512 | `COMPSIG-MLDSA65-Ed25519-SHA512` |
| ML-DSA-87-Ed448 | ML-DSA-87 | Ed448 | SHAKE256(64) | `COMPSIG-MLDSA87-Ed448-SHAKE256` |

## Message construction

Per the draft, signing operates on the representative `M'`, not the raw payload:

```
M' := Prefix || Label || 0x00 || PH(M)
Prefix = "CompositeAlgorithmSignatures2025"   // fixed 32-byte ASCII
Label  = per-algorithm domain separator (table above)
0x00   = empty-context length byte
PH(M)  = per-algorithm pre-hash of the raw JWS signing input
```

Both component signers sign the same `M'`. Verification requires **both** component signatures to verify.

## JWK shape

The JWK uses the existing `AKP` (Algorithm Key Pair) key type already provided by jwx v4. Composite algorithms share the `AKP` key type with pure ML-DSA and ML-KEM — the `alg` field is the discriminator, which is exactly how `jwk/akp.go:akpKeyKind()` already computes `KeyKind("AKP:" + alg.String())`.

```json
{
  "kty": "AKP",
  "alg": "ML-DSA-44-ES256",
  "pub":  "<base64url(mldsa_pub || uncompressed_ecdsa_point)>",
  "priv": "<base64url(mldsa_32byte_seed || ecdsa_scalar)>"
}
```

- `"pub"` = `mldsa_pub || traditional_pub`
- `"priv"` = `mldsa_32byte_seed || traditional_priv`
- ECDSA public keys are encoded uncompressed (`0x04 || X || Y`).
- Signatures are `mldsa_sig || traditional_sig` in exactly that order.
- ECDSA *signatures* are ASN.1 DER-encoded `Ecdsa-Sig-Value` (inherited from LAMPS) — **not** the JOSE `r‖s` fixed-length encoding. This is the one place the composite format diverges from usual JOSE conventions.

## Signature dispatch

The compsig module plugs into jwx v4's existing extension points:

| Registration | What | Why |
|--------------|------|-----|
| `jwa.RegisterSignatureAlgorithm()` | 6 composite algs | Makes them recognizable by `jwa.LookupSignatureAlgorithm` |
| `jws.RegisterAlgorithmForKeyType(AKP, alg)` | Associate algs with AKP | So `jwk → algs` lookups surface composite variants |
| `dsig.RegisterAlgorithm(name, Custom, meta)` | 6 Custom dsig impls | Actual signing/verification workhorse |
| `jwsbb.RegisterDsigAlgorithm(jwsAlg, dsigAlg)` | 6 mappings | Lets `jwsbb.Sign/Verify` dispatch to the Custom family |
| `jws.RegisterSigner` / `RegisterVerifier` | 6 + 6 | Thin JWK-unwrapping wrappers that call `jwsbb.Sign/Verify` |
| `jwk.RegisterKeyExporter(KeyKind("AKP:<alg>"), ...)` | 6 exporters | JWK → raw `*compsig.PrivateKey/PublicKey` |
| `jwk.RegisterKeyImporter(...)` | 2 importers | Raw `*compsig.PrivateKey/PublicKey` → JWK |

The six dsig Custom impls all live in `compSigDsig`, parameterized by an `algInfo` table entry.

## Coupling to jwx-go/mldsa and jwx-go/ed448

The compsig module depends on `github.com/jwx-go/mldsa/v4` and `github.com/jwx-go/ed448/v4` via `import _` side-effect imports:

- The ML-DSA component of every composite variant calls `jwsbb.Sign(..., "ML-DSA-44/65/87", ...)`, which dispatches to the `dsig.Custom` impl that `jwx-go/mldsa` registered at init time.
- The Ed448 component of `ML-DSA-87-Ed448` calls `jwsbb.Sign(..., "Ed448", ...)`, dispatching to the `dsig-circl-ed448` adapter that `jwx-go/ed448` pulled in at init time.

This avoids re-implementing the `filippo.io/mldsa` and `cloudflare/circl/sign/ed448` adapters in compsig, at the cost of a transitive dependency on both companion modules. Users who import compsig also get pure ML-DSA and Ed448 registered — one-stop import for the PQ algorithms.

ECDSA and Ed25519 components do **not** dispatch through jwsbb:

- **ECDSA**: the JOSE-standard `jwsbb.Sign("ES256", ...)` produces JWS `r‖s`, but the composite format demands LAMPS-style ASN.1 DER. compsig calls `crypto/ecdsa.SignASN1` / `VerifyASN1` directly.
- **Ed25519**: works either way; compsig uses `crypto/ed25519` directly to avoid an unnecessary dispatch hop.

## Files

```
.companions/repo/compsig/
├── compsig.go       // package doc, init() registration, side-effect imports
├── params.go        // algInfo table, prehash fns, traditional-op handlers
├── message.go       // composeMessage()
├── keys.go          // PrivateKey/PublicKey types, GenerateKey, Marshal/New
├── dsig.go          // compSigDsig (dsig.Custom Signer/Verifier)
├── signer.go        // jws.Signer wrapper (JWK unwrap + jwsbb dispatch)
├── verifier.go      // jws.Verifier wrapper
├── jwk.go           // importPrivateKey/importPublicKey/exportKey
├── compsig_test.go  // compose/keys tests
└── roundtrip_test.go // full sign/verify + JWK + tamper tests
```

## Test coverage

All six variants are exercised via table tests:

- `GenerateKey → Public` round-trip
- `MarshalBinary → NewPrivateKey`/`NewPublicKey` round-trip (both pub and priv)
- Length rejection, cross-algorithm rejection for public keys
- Deterministic `MarshalBinary`
- `jws.Sign` with raw `*PrivateKey` then `jws.Verify` with raw `*PublicKey`
- `jwk.Import → json.Marshal → jwk.ParseKey → jws.Sign → jws.Verify`
- Tampered payload fails verification
- Tampered signature (first byte of ML-DSA half) fails verification

Test vectors from the draft are **not** yet wired up — the current draft markdown does not ship vectors, and the LAMPS reference vectors use ASN.1 structures that are not byte-compatible with JOSE. This is noted in the module README as a known gap.

## Status / risks

- **Draft is `-01`**. Algorithm identifiers, labels, and pre-hash assignments are copied verbatim from the draft text as of 27 Feb 2026. They may shift in future drafts; users should not assume stable on-wire compatibility until WG Last Call.
- **ECDSA encoding divergence**. The LAMPS-style DER encoding is unusual for JOSE and may surprise integrators who assume `r‖s`. The `CLAUDE.md` and README both call this out explicitly.
- **jwx-go/mldsa and jwx-go/ed448 version drift**. compsig's `go.mod` requires specific versions of both companion modules; when either publishes a new release, compsig must track it. The `/jwx-companion-bulk` skill already handles this kind of sync once the remote repo exists.
