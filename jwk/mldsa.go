//go:build go1.27

package jwk

import (
	"bytes"
	"crypto/mldsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

// ML-DSA (FIPS 204) keys are carried in the AKP key type defined by RFC 9802.
// The AKP container itself is toolchain-independent and lives in akp.go; only
// the conversion to and from crypto/mldsa's key types is gated on Go 1.27,
// because that is when crypto/mldsa joins the standard library.
func init() {
	if err := RegisterKeyImporter(KeyImportFunc[*mldsa.PrivateKey](importMLDSAPrivateKey)); err != nil {
		panic(fmt.Sprintf("jwk: failed to register ML-DSA private key importer: %s", err))
	}
	if err := RegisterKeyImporter(KeyImportFunc[*mldsa.PublicKey](importMLDSAPublicKey)); err != nil {
		panic(fmt.Sprintf("jwk: failed to register ML-DSA public key importer: %s", err))
	}

	// AKP keys report a KeyKind of "AKP:<alg>", so the exporter is registered
	// once per parameter set. The bare "AKP" kind is left alone: it is shared
	// with other AKP algorithms such as ML-KEM, which jwx does not implement.
	for _, params := range mldsaParameterSets() {
		kind := KeyKind(jwa.AKP().String() + ":" + params.String())
		if err := RegisterKeyExporter(kind, KeyExportFunc(exportMLDSAKey)); err != nil {
			panic(fmt.Sprintf("jwk: failed to register ML-DSA key exporter for %s: %s", params, err))
		}
	}
}

// mldsaParameterSets returns the three parameter sets defined in FIPS 204.
func mldsaParameterSets() []mldsa.Parameters {
	return []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()}
}

// mldsaParamsForAlg maps a JWS "alg" value to its ML-DSA parameter set.
// The boolean is false for any algorithm that is not an ML-DSA variant.
func mldsaParamsForAlg(alg string) (mldsa.Parameters, bool) {
	for _, params := range mldsaParameterSets() {
		if params.String() == alg {
			return params, true
		}
	}
	return mldsa.Parameters{}, false
}

// importMLDSAPrivateKey converts a *mldsa.PrivateKey to a jwk.Key.
func importMLDSAPrivateKey(raw *mldsa.PrivateKey) (Key, error) {
	if raw == nil {
		return nil, fmt.Errorf(`jwk: cannot import nil *mldsa.PrivateKey`)
	}
	pub := raw.PublicKey()

	key := newAKPPrivateKey()
	if err := key.Set(AlgorithmKey, pub.Parameters().String()); err != nil {
		return nil, fmt.Errorf(`jwk: failed to set "alg" on ML-DSA private key: %w`, err)
	}
	if err := key.Set(AKPPubKey, pub.Bytes()); err != nil {
		return nil, fmt.Errorf(`jwk: failed to set "pub" on ML-DSA private key: %w`, err)
	}
	if err := key.Set(AKPPrivKey, raw.Bytes()); err != nil {
		return nil, fmt.Errorf(`jwk: failed to set "priv" on ML-DSA private key: %w`, err)
	}
	return key, nil
}

// importMLDSAPublicKey converts a *mldsa.PublicKey to a jwk.Key.
func importMLDSAPublicKey(raw *mldsa.PublicKey) (Key, error) {
	if raw == nil {
		return nil, fmt.Errorf(`jwk: cannot import nil *mldsa.PublicKey`)
	}

	key := newAKPPublicKey()
	if err := key.Set(AlgorithmKey, raw.Parameters().String()); err != nil {
		return nil, fmt.Errorf(`jwk: failed to set "alg" on ML-DSA public key: %w`, err)
	}
	if err := key.Set(AKPPubKey, raw.Bytes()); err != nil {
		return nil, fmt.Errorf(`jwk: failed to set "pub" on ML-DSA public key: %w`, err)
	}
	return key, nil
}

// exportMLDSAKey converts an AKP jwk.Key to a raw crypto/mldsa key.
func exportMLDSAKey(key Key, _ any) (any, error) {
	algV, ok := key.Algorithm()
	if !ok {
		return nil, fmt.Errorf(`jwk: AKP key is missing the required "alg" field`)
	}

	params, ok := mldsaParamsForAlg(algV.String())
	if !ok {
		// Some other AKP algorithm. Let the next exporter in the chain try.
		return nil, ContinueError()
	}

	pubV, ok := key.Field(AKPPubKey)
	if !ok {
		return nil, fmt.Errorf(`jwk: AKP key is missing the required "pub" field`)
	}
	pubBytes, ok := pubV.([]byte)
	if !ok {
		return nil, fmt.Errorf(`jwk: AKP key "pub" field is %T, expected []byte`, pubV)
	}

	privV, hasPriv := key.Field(AKPPrivKey)
	if !hasPriv {
		pk, err := mldsa.NewPublicKey(params, pubBytes)
		if err != nil {
			return nil, fmt.Errorf(`jwk: failed to construct ML-DSA public key: %w`, err)
		}
		return pk, nil
	}

	privBytes, ok := privV.([]byte)
	if !ok {
		return nil, fmt.Errorf(`jwk: AKP key "priv" field is %T, expected []byte`, privV)
	}

	sk, err := mldsa.NewPrivateKey(params, privBytes)
	if err != nil {
		return nil, fmt.Errorf(`jwk: failed to construct ML-DSA private key: %w`, err)
	}

	// "priv" is the seed the whole key pair is derived from, so a "pub" that
	// disagrees with it means the JWK is inconsistent. Returning the derived
	// key regardless would silently ignore the attacker-supplied half of a
	// tampered JWK.
	if derived := sk.PublicKey().Bytes(); !bytes.Equal(derived, pubBytes) {
		return nil, fmt.Errorf(`jwk: AKP key "pub" does not match the public key derived from "priv"`)
	}
	return sk, nil
}
