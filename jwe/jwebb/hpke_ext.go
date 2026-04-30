package jwebb

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
)

// HPKEKeyEncrypter is implemented by raw public key types that can
// perform HPKE key encryption for JWE. This allows external modules
// to provide HPKE support for KEM types not in Go's standard library
// (e.g., DHKEM(X448) from cloudflare/circl).
//
// When jwe.Encrypt encounters a raw key implementing this interface
// in the HPKE path, it delegates encryption to the key itself.
type HPKEKeyEncrypter interface {
	// EncryptHPKE encrypts the CEK using HPKE.
	//
	// alg is the HPKE algorithm identifier (e.g., "HPKE-5-KE").
	// calg is the content encryption algorithm bound into the HPKE info.
	//
	// Returns the sealed (encrypted) CEK and the encapsulated key (enc).
	EncryptHPKE(cek []byte, alg, calg string) (sealedCEK, enc []byte, err error)
}

// HPKEKeyDecrypter is implemented by raw private key types that can
// perform HPKE key decryption for JWE.
type HPKEKeyDecrypter interface {
	// DecryptHPKE decrypts the sealed CEK using HPKE.
	//
	// alg is the HPKE algorithm identifier.
	// calg is the content encryption algorithm.
	// sealedCEK is the encrypted CEK from the JWE Encrypted Key field.
	// enc is the encapsulated key from the "ek" header field.
	DecryptHPKE(sealedCEK []byte, alg, calg string, enc []byte) ([]byte, error)
}

// KeyEncryptHPKECustom encrypts using a custom HPKE key encrypter.
func KeyEncryptHPKECustom(cek []byte, alg, calg string, enc HPKEKeyEncrypter) (keygen.ByteSource, error) {
	sealedCEK, encKey, err := enc.EncryptHPKE(cek, alg, calg)
	if err != nil {
		return nil, fmt.Errorf(`HPKE key encrypt (custom): %w`, err)
	}

	return keygen.ByteWithEncapsulatedKey{
		ByteKey:    keygen.ByteKey(sealedCEK),
		Ciphertext: encKey,
	}, nil
}

// KeyDecryptHPKECustom decrypts using a custom HPKE key decrypter.
func KeyDecryptHPKECustom(sealedCEK []byte, alg, calg string, dec HPKEKeyDecrypter, enc []byte) ([]byte, error) {
	cek, err := dec.DecryptHPKE(sealedCEK, alg, calg, enc)
	if err != nil {
		return nil, fmt.Errorf(`HPKE key decrypt (custom): %w`, err)
	}
	return cek, nil
}

var (
	muHPKEAlgs sync.RWMutex
	hpkeAlgSet = map[string]struct{}{}
)

func init() {
	// Pre-register built-in HPKE algorithms so that IsHPKE uses a
	// single lookup path for both built-in and dynamically registered algorithms.
	for _, alg := range []string{
		tokens.HPKE_0_KE,
		tokens.HPKE_1_KE,
		tokens.HPKE_2_KE,
		tokens.HPKE_3_KE,
		tokens.HPKE_4_KE,
		tokens.HPKE_7_KE,
	} {
		if err := RegisterHPKEAlgorithm(alg); err != nil {
			panic(fmt.Sprintf("jwebb: failed to register builtin HPKE algorithm: %s", err))
		}
	}
}

// RegisterHPKEAlgorithm registers an algorithm identifier as an HPKE
// algorithm. After registration, IsHPKE returns true for this identifier,
// causing the JWE encrypt/decrypt dispatch to route it through the HPKE
// path. Registration is idempotent.
//
// # Privileged extension point
//
// This registry is an extension point on purpose: extension modules
// (the canonical example is github.com/jwx-go/mlkem) install support
// for new key-encryption algorithm identifiers from init(). Override
// of an existing identifier — including a built-in HPKE token or a
// non-HPKE token from another family (RSA, AES-KW, ECDH-ES, PBES2,
// dir) — is allowed by design: an extension may legitimately need
// to swap a default dispatch, and a programmatic check would either
// break that pattern or be trivially bypassable (since extensions
// can call any Register* from init()).
//
// Because override is the design, this function does NOT refuse
// re-registration of any identifier and does NOT verify the caller's
// intent. Anything in your import graph at init() can reshape the
// HPKE dispatch surface. The supply-chain risk this implies lives one
// layer up: audit your transitive dependencies, pin your go.mod, and
// treat extensions that touch this registry the same way you would
// treat any other init()-time hook into your crypto path. Contrast
// with closed-set registers like jwk/ecdsa.RegisterCurve, which DO
// refuse to re-register built-ins because no legitimate extension
// wants to swap a built-in NIST curve.
//
// Companion modules calling this from init() must check the returned
// error and panic on failure to stay forward-compatible — even though
// the current implementation always returns nil, the error return is
// part of the contract.
func RegisterHPKEAlgorithm(alg string) error {
	muHPKEAlgs.Lock()
	defer muHPKEAlgs.Unlock()
	hpkeAlgSet[alg] = struct{}{}
	return nil
}

func unregisterHPKEAlgorithm(alg string) {
	muHPKEAlgs.Lock()
	defer muHPKEAlgs.Unlock()
	delete(hpkeAlgSet, alg)
}

// isRegisteredHPKE checks whether alg is a registered HPKE algorithm.
func isRegisteredHPKE(alg string) bool {
	muHPKEAlgs.RLock()
	defer muHPKEAlgs.RUnlock()
	_, ok := hpkeAlgSet[alg]
	return ok
}
