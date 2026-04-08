# Extension Modules

In v4, optional signature algorithms are provided as standalone modules under [`github.com/jwx-go`](https://github.com/jwx-go). Each module registers its algorithms, key importers/exporters, and JWS signers/verifiers automatically via `init()` — just import the module for its side effects.

| Module | Algorithm | Key Package |
|:-------|:----------|:------------|
| [`github.com/jwx-go/mldsa/v4`](https://github.com/jwx-go/mldsa) | ML-DSA-44, ML-DSA-65, ML-DSA-87 | [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa) |
| [`github.com/jwx-go/ed448/v4`](https://github.com/jwx-go/ed448) | EdDSA (Ed448) | [`github.com/cloudflare/circl/sign/ed448`](https://pkg.go.dev/github.com/cloudflare/circl/sign/ed448) |
| [`github.com/jwx-go/es256k/v4`](https://github.com/jwx-go/es256k) | ES256K (secp256k1) | [`github.com/decred/dcrd/dcrec/secp256k1/v4`](https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4) |

* [ML-DSA (Post-Quantum Signatures)](#ml-dsa-post-quantum-signatures)
  * [Signing and Verifying](#signing-and-verifying)
  * [Working with JWK](#working-with-jwk)
  * [Exporting Keys](#exporting-keys)
* [Ed448](#ed448)
* [ES256K (secp256k1)](#es256k-secp256k1)

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
source: [examples/mldsa_sign_verify_example_test.go](https://github.com/jwx-go/examples/blob/main/mldsa_sign_verify_example_test.go)

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
source: [examples/mldsa_jwk_example_test.go](https://github.com/jwx-go/examples/blob/main/mldsa_jwk_example_test.go)

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
source: [examples/mldsa_export_example_test.go](https://github.com/jwx-go/examples/blob/main/mldsa_export_example_test.go)

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
source: [examples/jws_ed448_example_test.go](https://github.com/jwx-go/examples/blob/main/jws_ed448_example_test.go)

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
source: [examples/jws_sign_es256k_example_test.go](https://github.com/jwx-go/examples/blob/main/jws_sign_es256k_example_test.go)
