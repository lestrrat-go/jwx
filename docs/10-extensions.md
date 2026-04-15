# Extension Modules

In v4, optional features are provided as standalone modules under [`github.com/jwx-go`](https://github.com/jwx-go). Each module registers itself automatically via `init()` — just import the module for its side effects.

> **Note**: Extension modules register their algorithms from `init()` and **panic** if registration fails. This is intentional: a failed registration means the extension is unusable, and panicking at import time surfaces the problem immediately rather than at a later, confusing call site. See each module's package godoc for details.

### Signature Algorithms

| Module | Algorithm | Key Package |
|:-------|:----------|:------------|
| [`github.com/jwx-go/mldsa/v4`](https://github.com/jwx-go/mldsa) | ML-DSA-44, ML-DSA-65, ML-DSA-87 | [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa) |
| [`github.com/jwx-go/ed448/v4`](https://github.com/jwx-go/ed448) | EdDSA (Ed448) | [`github.com/cloudflare/circl/sign/ed448`](https://pkg.go.dev/github.com/cloudflare/circl/sign/ed448) |
| [`github.com/jwx-go/es256k/v4`](https://github.com/jwx-go/es256k) | ES256K (secp256k1) | [`github.com/decred/dcrd/dcrec/secp256k1/v4`](https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4) |
| [`github.com/jwx-go/compsig/v4`](https://github.com/jwx-go/compsig) | ML-DSA composite signatures (ML-DSA-44/65/87 paired with ES256/ES384/Ed25519/Ed448) per draft-ietf-jose-pq-composite-sigs — **experimental, draft-spec** | [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa) + stdlib/circl |

### Key Agreement / Encryption

| Module | Capability | Key Package |
|:-------|:-----------|:------------|
| [`github.com/jwx-go/x448/v4`](https://github.com/jwx-go/x448) | X448 ECDH-ES, HPKE with DHKEM(X448) | [`github.com/cloudflare/circl/dh/x448`](https://pkg.go.dev/github.com/cloudflare/circl/dh/x448) |
| [`github.com/jwx-go/mlkem/v4`](https://github.com/jwx-go/mlkem) | ML-KEM-768/1024 (with and without AES key wrap) per draft-ietf-jose-pqc-kem — **experimental, draft-spec** | [`crypto/mlkem`](https://pkg.go.dev/crypto/mlkem) (jwx requires Go 1.26) |
| [`github.com/jwx-go/reddy-pqchpke/v4`](https://github.com/jwx-go/reddy-pqchpke) | Hybrid PQ HPKE (HPKE-10-KE, HPKE-11-KE) per draft-reddy-cose-jose-pqc-hybrid-hpke — **experimental, pre-WG-adoption** | [`github.com/cloudflare/circl/kem/xwing`](https://pkg.go.dev/github.com/cloudflare/circl/kem/xwing) |

### Tooling / Backends

| Module | Capability |
|:-------|:-----------|
| [`github.com/jwx-go/jwkfetch/v4`](https://github.com/jwx-go/jwkfetch) | HTTP JWK Set retrieval — one-shot `Client` and background-refreshed `Cache` (backed by [`httprc`](https://github.com/lestrrat-go/httprc)). Holds the HTTP fetch surface so the core jwx module doesn't depend on `net/http` or `httprc`. |
| [`github.com/jwx-go/asmbase64/v4`](https://github.com/jwx-go/asmbase64) | Assembly-optimized base64 backend via [`segmentio/asm`](https://github.com/segmentio/asm) |

* [ML-DSA (Post-Quantum Signatures)](#ml-dsa-post-quantum-signatures)
  * [Signing and Verifying](#signing-and-verifying)
  * [Working with JWK](#working-with-jwk)
  * [Exporting Keys](#exporting-keys)
* [Ed448](#ed448)
* [ES256K (secp256k1)](#es256k-secp256k1)
* [Composite Signatures (compsig)](#composite-signatures-compsig)
* [X448](#x448)
  * [HPKE-5-KE (AES-256-GCM)](#hpke-5-ke-aes-256-gcm)
  * [HPKE-6-KE (ChaCha20Poly1305)](#hpke-6-ke-chacha20poly1305)
* [ML-KEM](#ml-kem)
* [Hybrid PQ HPKE (reddy-pqchpke)](#hybrid-pq-hpke-reddy-pqchpke)
* [HTTP JWK Set Retrieval (jwkfetch)](#http-jwk-set-retrieval-jwkfetch)
* [Assembly base64 (asmbase64)](#assembly-base64-asmbase64)

---

# ML-DSA (Post-Quantum Signatures)

ML-DSA is a post-quantum digital signature scheme standardized in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). It comes in three parameter sets with increasing security levels:

| Parameter Set | NIST Level | Use Case |
|:--------------|:-----------|:---------|
| ML-DSA-44 | 2 | Smallest keys and signatures, fastest |
| ML-DSA-65 | 3 | Balanced security and performance |
| ML-DSA-87 | 5 | Highest security |

ML-DSA keys use the `"AKP"` (Algorithm Key Pair) JWK key type. Unlike traditional key types (RSA, EC), AKP keys **require** the `"alg"` field because the key type alone does not determine the algorithm.

To use ML-DSA, import [`github.com/jwx-go/mldsa/v4`](https://github.com/jwx-go/mldsa) for its side effects. Raw keys come from [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa).

## Signing and Verifying

```go
package examples_test

import (
	"fmt"

	"filippo.io/mldsa"
	jwxmldsa "github.com/jwx-go/mldsa/v4"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_mldsa_sign_verify() {
	// ML-DSA is a post-quantum digital signature scheme (FIPS 204).
	// To use it with jwx, import github.com/jwx-go/mldsa/v4 for its
	// side effects — the init() function registers ML-DSA algorithms,
	// key importers/exporters, and JWS signers/verifiers automatically.

	// Generate an ML-DSA-65 key pair. ML-DSA comes in three parameter sets:
	//   - ML-DSA-44 (NIST Level 2, smallest/fastest)
	//   - ML-DSA-65 (NIST Level 3, balanced)
	//   - ML-DSA-87 (NIST Level 5, highest security)
	// Each parameter set determines the key and signature sizes.
	// mldsa.GenerateKey takes a *mldsa.Parameters to select the variant.
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		fmt.Printf("failed to generate ML-DSA key: %s\n", err)
		return
	}

	payload := []byte("Hello, post-quantum world!")

	// jws.Sign accepts raw *mldsa.PrivateKey directly — the mldsa package's
	// init() registers a JWS signer that handles the conversion internally.
	// The algorithm (jwxmldsa.MLDSA65()) must match the key's parameter set;
	// using a mismatched algorithm (e.g., MLDSA44() with an ML-DSA-65 key)
	// will fail.
	signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA65(), sk))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}

	// Verification uses the public key extracted from the private key via
	// PublicKey(). Like signing, raw *mldsa.PublicKey is accepted directly.
	// You could also pass the private key itself — the verifier extracts
	// the public key internally.
	verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA65(), sk.PublicKey()))
	if err != nil {
		fmt.Printf("failed to verify signature: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// Hello, post-quantum world!
}
```
source: [examples/mldsa_sign_verify_example_test.go](https://github.com/jwx-go/examples/blob/v4/mldsa_sign_verify_example_test.go)

## Working with JWK

```go
package examples_test

import (
	"encoding/json"
	"fmt"

	"filippo.io/mldsa"
	jwxmldsa "github.com/jwx-go/mldsa/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_mldsa_jwk() {
	// ML-DSA keys can be represented as JWK using the "AKP" (Algorithm Key Pair)
	// key type. Unlike traditional key types (RSA, EC) where the algorithm is
	// optional, AKP keys REQUIRE the "alg" field because the key type alone
	// does not determine the algorithm — the parameter set (ML-DSA-44/65/87)
	// must be specified explicitly.

	// Generate a raw ML-DSA-44 key pair using the filippo.io/mldsa package.
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		fmt.Printf("failed to generate ML-DSA key: %s\n", err)
		return
	}

	// jwk.Import converts the raw *mldsa.PrivateKey into a jwk.Key.
	// The mldsa package registers a key importer during init(), so jwx
	// knows how to handle *mldsa.PrivateKey without any extra setup.
	// The resulting JWK will have kty="AKP", alg="ML-DSA-44", and both
	// "pub" and "priv" fields populated.
	privJWK, err := jwk.Import[jwk.Key](sk)
	if err != nil {
		fmt.Printf("failed to import key to JWK: %s\n", err)
		return
	}

	fmt.Printf("kty: %s\n", privJWK.KeyType())

	alg, ok := privJWK.Algorithm()
	if !ok {
		fmt.Println("missing algorithm")
		return
	}
	fmt.Printf("alg: %s\n", alg)

	// JWK keys can be serialized to JSON for storage or transmission.
	// The JSON representation follows the AKP key format with base64url-encoded
	// "pub" (public key bytes) and "priv" (seed bytes) fields.
	serialized, err := json.Marshal(privJWK)
	if err != nil {
		fmt.Printf("failed to serialize JWK: %s\n", err)
		return
	}

	// Parse back from JSON. Because the mldsa package registered the ML-DSA
	// signature algorithms at init time, jwk.ParseKey can resolve "ML-DSA-44"
	// in the "alg" field and reconstruct the key correctly.
	parsed, err := jwk.ParseKey[jwk.Key](serialized)
	if err != nil {
		fmt.Printf("failed to parse JWK: %s\n", err)
		return
	}

	// The parsed JWK key is fully functional — it can be used for signing
	// just like the original. This demonstrates that JWK serialization
	// round-trips correctly for ML-DSA keys.
	payload := []byte("round-trip test")
	signed, err := jws.Sign(payload, jws.WithKey(jwxmldsa.MLDSA44(), parsed))
	if err != nil {
		fmt.Printf("failed to sign with parsed JWK: %s\n", err)
		return
	}

	// Derive the public JWK from the private JWK for verification.
	// PublicKey() strips the "priv" field, leaving only "pub".
	pubJWK, err := parsed.PublicKey()
	if err != nil {
		fmt.Printf("failed to derive public key: %s\n", err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA44(), pubJWK))
	if err != nil {
		fmt.Printf("failed to verify with public JWK: %s\n", err)
		return
	}

	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// kty: AKP
	// alg: ML-DSA-44
	// round-trip test
}
```
source: [examples/mldsa_jwk_example_test.go](https://github.com/jwx-go/examples/blob/v4/mldsa_jwk_example_test.go)

## Exporting Keys

```go
package examples_test

import (
	"fmt"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

func Example_mldsa_export() {
	// jwk.Export converts a jwk.Key back to a raw key type. For ML-DSA keys,
	// this returns *mldsa.PrivateKey or *mldsa.PublicKey depending on whether
	// the JWK contains the "priv" field.
	//
	// This is useful when you receive an ML-DSA key in JWK format (e.g., from
	// a JWKS endpoint or configuration file) and need the raw key for operations
	// outside of jwx.

	// Generate an ML-DSA-87 key pair — the highest security level (NIST Level 5).
	sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		fmt.Printf("failed to generate ML-DSA key: %s\n", err)
		return
	}

	// Import the raw key into JWK format.
	privJWK, err := jwk.Import[jwk.Key](sk)
	if err != nil {
		fmt.Printf("failed to import key: %s\n", err)
		return
	}

	// Export back to a raw key. jwk.Export[any] lets the registered exporter
	// choose the most appropriate concrete type. For AKP keys with an ML-DSA
	// algorithm, the mldsa package's exporter returns *mldsa.PrivateKey.
	// The exporter reconstructs the key from the stored seed ("priv" field)
	// and verifies that the derived public key matches the "pub" field.
	exported, err := jwk.Export[any](privJWK)
	if err != nil {
		fmt.Printf("failed to export key: %s\n", err)
		return
	}

	exportedSK, ok := exported.(*mldsa.PrivateKey)
	if !ok {
		fmt.Printf("unexpected key type: %T\n", exported)
		return
	}

	// The exported key is identical to the original — the import/export
	// cycle is lossless.
	fmt.Printf("key type: %s\n", jwa.AKP())
	fmt.Printf("keys match: %t\n", sk.Equal(exportedSK))
	// OUTPUT:
	// key type: AKP
	// keys match: true
}
```
source: [examples/mldsa_export_example_test.go](https://github.com/jwx-go/examples/blob/v4/mldsa_export_example_test.go)

---

# Ed448

Ed448 is an Edwards curve providing ~224-bit security (NIST Level 3). It uses the EdDSA signature scheme but with a different curve than Ed25519.

To use Ed448, import [`github.com/jwx-go/ed448/v4`](https://github.com/jwx-go/ed448) for its side effects. Raw keys come from [`github.com/cloudflare/circl/sign/ed448`](https://pkg.go.dev/github.com/cloudflare/circl/sign/ed448).

```go
package examples_test

import (
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	ed448ext "github.com/jwx-go/ed448/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_ed448() {
	// Generate an Ed448 key pair
	pub, priv, err := ed448.GenerateKey(nil)
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	payload := []byte("Hello, Ed448!")

	// Sign and verify with raw keys
	signed, err := jws.Sign(payload, jws.WithKey(ed448ext.EdDSAEd448(), priv))
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(ed448ext.EdDSAEd448(), pub))
	if err != nil {
		fmt.Printf("failed to verify: %s\n", err)
		return
	}
	fmt.Printf("%s\n", verified)

	// Import raw keys into JWK
	jwkPriv, err := jwk.Import[jwk.Key](priv)
	if err != nil {
		fmt.Printf("failed to import private key: %s\n", err)
		return
	}

	jwkPub, err := jwk.Import[jwk.Key](pub)
	if err != nil {
		fmt.Printf("failed to import public key: %s\n", err)
		return
	}

	// Sign and verify with JWK keys
	signed, err = jws.Sign(payload, jws.WithKey(ed448ext.EdDSAEd448(), jwkPriv))
	if err != nil {
		fmt.Printf("failed to sign with JWK key: %s\n", err)
		return
	}

	verified, err = jws.Verify(signed, jws.WithKey(ed448ext.EdDSAEd448(), jwkPub))
	if err != nil {
		fmt.Printf("failed to verify with JWK key: %s\n", err)
		return
	}
	fmt.Printf("%s\n", verified)

	// JWK JSON round-trip
	buf, err := json.MarshalIndent(jwkPriv, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal JWK: %s\n", err)
		return
	}

	parsed, err := jwk.ParseKey[jwk.Key](buf)
	if err != nil {
		fmt.Printf("failed to parse JWK: %s\n", err)
		return
	}
	_ = parsed

	// Output:
	// Hello, Ed448!
	// Hello, Ed448!
}
```
source: [examples/jws_ed448_example_test.go](https://github.com/jwx-go/examples/blob/v4/jws_ed448_example_test.go)

---

# ES256K (secp256k1)

ES256K is the ECDSA signature algorithm using the secp256k1 curve and SHA-256. It is widely used in blockchain ecosystems (Bitcoin, Ethereum) but is not part of the core JWA standard.

To use ES256K, import [`github.com/jwx-go/es256k/v4`](https://github.com/jwx-go/es256k) for its side effects. Because ES256K uses standard ECDSA, keys are regular `*ecdsa.PrivateKey` / `*ecdsa.PublicKey` with the secp256k1 curve from [`github.com/decred/dcrd/dcrec/secp256k1/v4`](https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4). JWK representation uses `kty="EC"` with `crv="secp256k1"`.

```go
package examples_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	jwxes256k "github.com/jwx-go/es256k/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_sign_es256k() {
	// ES256K is the ECDSA signature algorithm using the secp256k1 curve
	// and SHA-256. It is widely used in blockchain ecosystems (Bitcoin,
	// Ethereum) but is not part of the core JWA standard — jwx provides
	// it as an opt-in extension via github.com/jwx-go/es256k/v4.
	//
	// Importing the package for side effects registers:
	//   - The "secp256k1" elliptic curve in jwa
	//   - The "ES256K" signature algorithm in jwa/jws
	//   - The curve-to-ECDSA mapping so jwk can handle secp256k1 keys
	//
	// After registration, secp256k1 keys work like any other ECDSA key
	// (P-256, P-384, etc.) throughout jwx.

	// Generate an ECDSA key on the secp256k1 curve. Because ES256K uses
	// standard ECDSA, key generation uses crypto/ecdsa with the secp256k1
	// curve from the dcrd library — there is no custom key type.
	privkey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader) //nolint:staticcheck
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	payload := []byte("Hello, secp256k1!")

	// Sign the payload with ES256K. jws.WithKey takes the algorithm
	// identifier and the raw *ecdsa.PrivateKey — no JWK wrapping needed.
	// The registered signer maps ES256K to the secp256k1+SHA-256 dsig
	// algorithm internally.
	signed, err := jws.Sign(payload, jws.WithKey(jwxes256k.ES256K(), privkey))
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	// Verification can use either a raw *ecdsa.PublicKey or a jwk.Key.
	// Here we demonstrate both approaches.

	// Approach 1: verify with the raw public key directly.
	verified, err := jws.Verify(signed, jws.WithKey(jwxes256k.ES256K(), &privkey.PublicKey))
	if err != nil {
		fmt.Printf("failed to verify with raw key: %s\n", err)
		return
	}
	fmt.Printf("%s\n", verified)

	// Approach 2: import the public key into a JWK first, then verify.
	// This is useful when distributing keys in JWK format — the resulting
	// JWK will have kty="EC" and crv="secp256k1", the same structure as
	// any other EC key.
	pubJWK, err := jwk.Import[jwk.Key](&privkey.PublicKey)
	if err != nil {
		fmt.Printf("failed to import public key: %s\n", err)
		return
	}

	verified, err = jws.Verify(signed, jws.WithKey(jwxes256k.ES256K(), pubJWK))
	if err != nil {
		fmt.Printf("failed to verify with JWK: %s\n", err)
		return
	}
	fmt.Printf("%s\n", verified)
	// OUTPUT:
	// Hello, secp256k1!
	// Hello, secp256k1!
}
```
source: [examples/jws_sign_es256k_example_test.go](https://github.com/jwx-go/examples/blob/v4/jws_sign_es256k_example_test.go)

## Signature malleability (low-S)

ES256K signatures produced and accepted by this module do **not** enforce low-S canonicalization. The underlying `crypto/ecdsa` implementation may emit either of the two mathematically valid `(r, s)` / `(r, n-s)` pairs, and verification accepts both. This matches every other ECDSA algorithm in `jwx` (ES256, ES384, ES512) and is appropriate for JWS, where signatures are bound to a specific payload and are not used as unique identifiers.

If you are bridging JWS-signed material into a system that treats ECDSA signatures as unique identifiers (e.g. Bitcoin-style transaction hashes, or signature-equality caches), you are responsible for applying low-S normalization yourself. Do not assume two verifiable ES256K signatures over the same payload are byte-equal.

---

# X448

X448 is an elliptic curve providing ~224-bit security for key agreement. Unlike X25519, X448 is not in Go's standard library, so jwx v4 provides it as an extension module.

To use X448, import [`github.com/jwx-go/x448/v4`](https://github.com/jwx-go/x448) for its side effects. Raw keys come from [`github.com/cloudflare/circl/dh/x448`](https://pkg.go.dev/github.com/cloudflare/circl/dh/x448). After import, X448 keys work with JWK (`kty=OKP`, `crv=X448`), ECDH-ES key agreement, and HPKE (HPKE-5-KE, HPKE-6-KE).

## HPKE-5-KE (AES-256-GCM)

<!-- INCLUDE(examples/jwe_encrypt_hpke5_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "fmt"

  circlx448 "github.com/cloudflare/circl/dh/x448"
  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
  "github.com/lestrrat-go/jwx/v4/jwk"

  // Importing x448 registers X448 key support, ECDH-ES key agreement,
  // and HPKE algorithms (HPKE-5-KE, HPKE-6-KE) with jwx. Without this
  // import, jwx does not know how to handle OKP keys with curve "X448"
  // or the HPKE key encryption algorithms.
  x448mod "github.com/jwx-go/x448/v4"
)

func Example_jwe_encrypt_hpke5() {
  // HPKE (Hybrid Public Key Encryption) is a modern key encapsulation
  // mechanism defined in RFC 9180, adapted for JOSE in
  // draft-ietf-jose-hpke-encrypt. It replaces traditional key wrapping
  // (e.g., RSA-OAEP, ECDH-ES+A256KW) with a KEM/KDF/AEAD triple.
  //
  // HPKE-5-KE uses:
  //   - KEM:  DHKEM(X448, HKDF-SHA512)
  //   - KDF:  HKDF-SHA512
  //   - AEAD: AES-256-GCM
  //
  // The "-KE" suffix indicates Key Encryption mode, where HPKE encrypts
  // the Content Encryption Key (CEK) rather than the payload directly.
  // The CEK then encrypts the actual payload using the content encryption
  // algorithm (e.g., A256GCM).

  // Generate an X448 key pair. X448 is a Diffie-Hellman function on
  // Curve448 — it provides ~224-bit security, stronger than X25519's
  // ~128-bit level. Key generation uses cloudflare/circl because Go's
  // standard library does not include X448.
  var seed circlx448.Key
  if _, err := rand.Read(seed[:]); err != nil {
    fmt.Printf("failed to generate random seed: %s\n", err)
    return
  }

  var pub circlx448.Key
  circlx448.KeyGen(&pub, &seed)

  // Wrap the raw X448 key pair into the x448mod types that implement
  // jwx's key agreement interfaces. NewPrivateKey takes the seed (private
  // scalar) and the corresponding public key.
  privKey := x448mod.NewPrivateKey(seed, pub)

  // Import to JWK. The resulting key has kty="OKP" and crv="X448".
  // We need a JWK because jwe.Encrypt/Decrypt work with JWK keys
  // to embed the ephemeral public key in the JWE header.
  privJWK, err := jwk.Import[jwk.Key](privKey)
  if err != nil {
    fmt.Printf("failed to import private key: %s\n", err)
    return
  }

  // Derive the public JWK for encryption. In HPKE, the sender only
  // needs the recipient's public key — the KEM generates an ephemeral
  // key pair internally and includes the encapsulated key in the output.
  pubJWK, err := privJWK.PublicKey()
  if err != nil {
    fmt.Printf("failed to derive public key: %s\n", err)
    return
  }

  payload := []byte("Hello, HPKE with X448!")

  // Encrypt using HPKE-5-KE. The key encryption algorithm (HPKE-5-KE)
  // encapsulates the CEK using DHKEM(X448) + AES-256-GCM, while the
  // content encryption algorithm (A256GCM) encrypts the payload with
  // the CEK. These are independent choices — you can pair any HPKE
  // algorithm with any content encryption algorithm.
  encrypted, err := jwe.Encrypt(payload,
    jwe.WithKey(x448mod.HPKE5(), pubJWK),
    jwe.WithContentEncryption(jwa.A256GCM()),
  )
  if err != nil {
    fmt.Printf("failed to encrypt: %s\n", err)
    return
  }

  // Decrypt using the private JWK. The recipient uses their private key
  // to decapsulate the CEK from the HPKE ciphertext, then decrypts the
  // payload with the recovered CEK.
  decrypted, err := jwe.Decrypt(encrypted,
    jwe.WithKey(x448mod.HPKE5(), privJWK),
  )
  if err != nil {
    fmt.Printf("failed to decrypt: %s\n", err)
    return
  }

  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Hello, HPKE with X448!
}
```
source: [examples/jwe_encrypt_hpke5_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_encrypt_hpke5_example_test.go)
<!-- END INCLUDE -->

## HPKE-6-KE (ChaCha20Poly1305)

<!-- INCLUDE(examples/jwe_encrypt_hpke6_example_test.go) -->
```go
package examples_test

import (
  "crypto/rand"
  "fmt"

  circlx448 "github.com/cloudflare/circl/dh/x448"
  "github.com/lestrrat-go/jwx/v4/jwa"
  "github.com/lestrrat-go/jwx/v4/jwe"
  "github.com/lestrrat-go/jwx/v4/jwk"

  x448mod "github.com/jwx-go/x448/v4"
)

func Example_jwe_encrypt_hpke6() {
  // HPKE-6-KE is the ChaCha20Poly1305 variant of X448 HPKE:
  //   - KEM:  DHKEM(X448, HKDF-SHA512)
  //   - KDF:  HKDF-SHA512
  //   - AEAD: ChaCha20Poly1305
  //
  // Compared to HPKE-5-KE (which uses AES-256-GCM), HPKE-6-KE is
  // preferable on platforms without AES hardware acceleration, where
  // ChaCha20Poly1305 is significantly faster in software. The security
  // level is comparable — both provide 256-bit key strength.

  // Generate an X448 key pair using cloudflare/circl.
  var seed circlx448.Key
  if _, err := rand.Read(seed[:]); err != nil {
    fmt.Printf("failed to generate random seed: %s\n", err)
    return
  }

  var pub circlx448.Key
  circlx448.KeyGen(&pub, &seed)

  privKey := x448mod.NewPrivateKey(seed, pub)

  privJWK, err := jwk.Import[jwk.Key](privKey)
  if err != nil {
    fmt.Printf("failed to import private key: %s\n", err)
    return
  }

  pubJWK, err := privJWK.PublicKey()
  if err != nil {
    fmt.Printf("failed to derive public key: %s\n", err)
    return
  }

  payload := []byte("Hello, HPKE-6-KE with ChaCha20!")

  // Encrypt using HPKE-6-KE. The only difference from HPKE-5-KE is
  // the AEAD used to encrypt the CEK — ChaCha20Poly1305 instead of
  // AES-256-GCM. The API is identical; the algorithm identifier
  // controls the internal AEAD selection.
  encrypted, err := jwe.Encrypt(payload,
    jwe.WithKey(x448mod.HPKE6(), pubJWK),
    jwe.WithContentEncryption(jwa.A256GCM()),
  )
  if err != nil {
    fmt.Printf("failed to encrypt: %s\n", err)
    return
  }

  decrypted, err := jwe.Decrypt(encrypted,
    jwe.WithKey(x448mod.HPKE6(), privJWK),
  )
  if err != nil {
    fmt.Printf("failed to decrypt: %s\n", err)
    return
  }

  fmt.Printf("%s\n", decrypted)
  // OUTPUT:
  // Hello, HPKE-6-KE with ChaCha20!
}
```
source: [examples/jwe_encrypt_hpke6_example_test.go](https://github.com/jwx-go/examples/blob/v4/jwe_encrypt_hpke6_example_test.go)
<!-- END INCLUDE -->

---

# Composite Signatures (compsig)

Composite signatures pair ML-DSA (FIPS 204) with a traditional signature scheme; both component signatures must verify for the composite to be accepted. This provides defense-in-depth during the transition to post-quantum cryptography — the signature remains secure as long as either component is unbroken. The module tracks [`draft-ietf-jose-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/).

> **Experimental.** Algorithm identifiers, JWK encoding, and on-wire formats may change until the draft reaches WG Last Call.

To use compsig, import [`github.com/jwx-go/compsig/v4`](https://github.com/jwx-go/compsig) for its side effects. The import transitively pulls in the `mldsa` and `ed448` modules, so pure ML-DSA-44/65/87 and Ed448 are also registered.

```go
import (
    compsig "github.com/jwx-go/compsig/v4"
    "github.com/lestrrat-go/jwx/v4/jws"
)

sk, _ := compsig.GenerateKey(compsig.MLDSA65ES256())
pub := sk.Public()

signed, _ := jws.Sign(payload, jws.WithKey(compsig.MLDSA65ES256(), sk))
verified, _ := jws.Verify(signed, jws.WithKey(compsig.MLDSA65ES256(), pub))
```

Composite keys use the `AKP` key type, discriminated by the `alg` field. Supported algorithms: `ML-DSA-44-ES256`, `ML-DSA-65-ES256`, `ML-DSA-87-ES384`, `ML-DSA-44-Ed25519`, `ML-DSA-65-Ed25519`, `ML-DSA-87-Ed448`. See [`examples/compsig_sign_verify_example_test.go`](https://github.com/jwx-go/examples/blob/v4/compsig_sign_verify_example_test.go) for a runnable example and the [module README](https://github.com/jwx-go/compsig) for the full algorithm table.

---

# ML-KEM

ML-KEM is a post-quantum key encapsulation mechanism standardized in [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final). The module implements the JWE bindings from [`draft-ietf-jose-pqc-kem`](https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/) using the stdlib `crypto/mlkem` package — no third-party dependency.

> **Experimental.** The draft is still in active IETF development. Once it is published as an RFC, ML-KEM support may fold into the main jwx module and this companion will be deprecated.

To use ML-KEM, import [`github.com/jwx-go/mlkem/v4`](https://github.com/jwx-go/mlkem) for its side effects. Keys use the `AKP` JWK key type.

```go
import (
    "crypto/mlkem"
    jwxmlkem "github.com/jwx-go/mlkem/v4"
    "github.com/lestrrat-go/jwx/v4/jwa"
    "github.com/lestrrat-go/jwx/v4/jwe"
)

dk, _ := mlkem.GenerateKey768()
ek := dk.EncapsulationKey()

encrypted, _ := jwe.Encrypt(payload,
    jwe.WithKey(jwxmlkem.MLKEM768(), ek),
    jwe.WithContentEncryption(jwa.A256GCM()),
)

decrypted, _ := jwe.Decrypt(encrypted, jwe.WithKey(jwxmlkem.MLKEM768(), dk))
```

Supported algorithms: `ML-KEM-768`, `ML-KEM-1024` (direct), and `ML-KEM-768+A192KW`, `ML-KEM-1024+A256KW` (key wrap variants). Raw `*mlkem.EncapsulationKey*`/`*mlkem.DecapsulationKey*` values and `jwk.Key` values are both accepted via `jwe.WithKey`. See [`examples/mlkem_encrypt_decrypt_example_test.go`](https://github.com/jwx-go/examples/blob/v4/mlkem_encrypt_decrypt_example_test.go) for a runnable example.

**JWK round-trip caveat:** `draft-ietf-jose-pqc-kem` defines the `priv` field as the 32-byte `d` seed only, while stdlib `crypto/mlkem` requires the full 64-byte `d || z` seed. On re-import, a fresh random `z` is generated. Decapsulation of valid ciphertexts is unaffected, but JWK round-trips are not bitwise-identical. See the [module README](https://github.com/jwx-go/mlkem) for details.

---

# Hybrid PQ HPKE (reddy-pqchpke)

Hybrid post-quantum HPKE key encryption pairing X25519 with ML-KEM-768 via the [X-Wing KEM](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/), SHAKE256 as the HPKE KDF, and AES-256-GCM or ChaCha20-Poly1305 as the AEAD. Tracks [`draft-reddy-cose-jose-pqc-hybrid-hpke`](https://datatracker.ietf.org/doc/draft-reddy-cose-jose-pqc-hybrid-hpke/).

> **Experimental, pre-WG-adoption.** This is an individual IETF submission, not a WG document. Algorithm identifiers, KDF info bytes, and key encodings may change without notice. Do not use for interoperable production traffic yet.

To use hybrid PQ HPKE, import [`github.com/jwx-go/reddy-pqchpke/v4`](https://github.com/jwx-go/reddy-pqchpke) for its side effects. The module registers AKP key import/export and two key-encryption-mode HPKE algorithms:

| Algorithm | KEM | KDF | AEAD |
|:----------|:----|:----|:-----|
| `HPKE-10-KE` | X25519+ML-KEM-768 (X-Wing) | SHAKE256 | AES-256-GCM |
| `HPKE-11-KE` | X25519+ML-KEM-768 (X-Wing) | SHAKE256 | ChaCha20-Poly1305 |

```go
import (
    _ "github.com/jwx-go/reddy-pqchpke/v4"
)
```

The module intentionally implements only the X25519+ML-KEM-768 ciphersuite (the only hybrid in the draft that corresponds to a named, peer-reviewed construction). See [`examples/pqchpke_encrypt_decrypt_example_test.go`](https://github.com/jwx-go/examples/blob/v4/pqchpke_encrypt_decrypt_example_test.go) for a runnable encrypt/decrypt example.

---

# HTTP JWK Set Retrieval (jwkfetch)

`jwkfetch` is the home for all HTTP-based JWK Set retrieval. It holds the HTTP fetch surface so the core jwx `jwk` package depends on neither `net/http` nor [`httprc`](https://github.com/lestrrat-go/httprc).

It offers two complementary types, both of which implement `jwk.Fetcher`:

- **`Client`** — one-shot HTTPS fetch. Use for ad-hoc retrievals and for `jku`-style verification where the URL comes from an untrusted JWS header.
- **`Cache`** — background-refreshed JWKS store backed by `httprc`. Use for a small, trusted set of issuer JWKS endpoints where amortizing fetch cost matters.

Both are **closed structs** constructed via functional options.

```go
import "github.com/jwx-go/jwkfetch/v4"

// --- one-shot fetch of a hard-coded / trusted-config URL ---
client := jwkfetch.NewClient()
set, err := client.Fetch(ctx, "https://issuer.example/jwks.json")

// --- one-shot fetch of a jku-header URL (untrusted source) ---
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
// Cache also implements jwk.Fetcher:
_, err = jws.Verify(signed, jws.WithVerifyAuto(cache))
```

A `Client` built with no `WithWhitelist` permits every URL, which is the right default when the URL is a compile-time constant or comes from trusted configuration. When the URL comes from an untrusted source (typically the `jku` header of a JWS) you MUST pass `WithWhitelist` with a restrictive allowlist — jwx does not wrap the fetcher in a default-deny. A restrictive `Whitelist` is applied to the initial URL and every redirect target.

Policy options (`WithHTTPClient`, `WithMaxBodySize`, `WithParseOptions`) work for both `NewClient` and `NewCache`. `WithWhitelist` is `Client`-only — `Cache` has no `Whitelist` concept because the URLs it will ever contact are exactly the ones you passed to `Register`. Passing `WithWhitelist` to `NewCache` is a compile-time error. Per-URL knobs passed to `Cache.Register` cover refresh interval (`WithConstantInterval` / `WithMinInterval` / `WithMaxInterval`) and `WithWaitReady`.

See the [module README](https://github.com/jwx-go/jwkfetch) for the full API reference and whitelist types (`InsecureWhitelist`, `BlockAllWhitelist`, `MapWhitelist`, `RegexpWhitelist`, `WhitelistFunc`).

---

# Assembly base64 (asmbase64)

`asmbase64` replaces jwx's default `encoding/base64` implementation with the assembly-optimized [`github.com/segmentio/asm/base64`](https://github.com/segmentio/asm) encoder/decoder. On amd64 with AVX2 this is meaningfully faster for the base64url workloads that dominate JWK/JWS/JWT parsing.

Activate via a blank import — no API surface of its own:

```go
import _ "github.com/jwx-go/asmbase64/v4"
```

The import registers an optimized RawURL encoder via `jwx.SetBase64Encoder()` and a decoder with automatic encoding detection via `jwx.SetBase64Decoder()`. All JWK, JWS, and JWT operations pick up the new backend automatically. See [`examples/jwx_asmbase64_example_test.go`](https://github.com/jwx-go/examples/blob/v4/jwx_asmbase64_example_test.go) for a runnable example.
