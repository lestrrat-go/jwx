//go:build go1.27

package jws

import (
	"bytes"
	"crypto/mldsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

// ML-DSA (FIPS 204) signing and verification. This file is gated on Go 1.27
// because that is when crypto/mldsa joins the standard library; on Go 1.26 the
// algorithms are not registered at all, so jws.Sign and jws.Verify report them
// as unsupported, instead of the confusing key error that would surface
// later.
func init() {
	for _, entry := range []struct {
		alg    jwa.SignatureAlgorithm
		params mldsa.Parameters
	}{
		{jwa.MLDSA44(), mldsa.MLDSA44()},
		{jwa.MLDSA65(), mldsa.MLDSA65()},
		{jwa.MLDSA87(), mldsa.MLDSA87()},
	} {
		name := entry.params.String()

		// dsig owns the algorithm itself from v1.4.0 on, including the
		// parameter-set check. It uses the same names as JOSE, so jwsbb's
		// fallback resolves them with no mapping registered here.
		if err := RegisterSigner(entry.alg, &mldsaSigner{algName: name, params: entry.params}); err != nil {
			panic(fmt.Sprintf("jws: failed to register signer for %s: %s", name, err))
		}
		if err := RegisterVerifier(entry.alg, &mldsaVerifier{algName: name, params: entry.params}); err != nil {
			panic(fmt.Sprintf("jws: failed to register verifier for %s: %s", name, err))
		}
		if err := RegisterAlgorithmForKeyType(jwa.AKP(), entry.alg); err != nil {
			panic(fmt.Sprintf("jws: failed to associate %s with the AKP key type: %s", name, err))
		}
	}
}

// requireMLDSAParamsMatch reports whether a caller-supplied key belongs to the
// parameter set the algorithm was registered for. crypto/mldsa's Parameters is
// a comparable value describing one of the three FIPS 204 sets, so a plain
// comparison is enough. A mismatch means the "alg" header and the key disagree,
// which is the shape an algorithm-confusion attempt takes.
func requireMLDSAParamsMatch(got, want mldsa.Parameters) error {
	if got != want {
		return fmt.Errorf(`ML-DSA parameter set mismatch: key is %s, algorithm is %s`, got, want)
	}
	return nil
}

// mldsaParamsForAlg maps a JWS "alg" value to its ML-DSA parameter set.
func mldsaParamsForAlg(alg string) (mldsa.Parameters, error) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		if params.String() == alg {
			return params, nil
		}
	}
	return mldsa.Parameters{}, fmt.Errorf(`unknown ML-DSA algorithm %q`, alg)
}

type mldsaSigner struct {
	algName string
	params  mldsa.Parameters
}

func (s *mldsaSigner) Sign(key any, payload []byte) ([]byte, error) {
	sk, err := mldsaPrivateKeyFrom(key, s.params)
	if err != nil {
		return nil, fmt.Errorf(`mldsa.Sign: %w`, err)
	}
	return jwsbb.Sign(sk, s.algName, payload, nil)
}

type mldsaVerifier struct {
	algName string
	params  mldsa.Parameters
}

func (v *mldsaVerifier) Verify(key any, payload, signature []byte) error {
	pk, err := mldsaPublicKeyFrom(key, v.params)
	if err != nil {
		return fmt.Errorf(`mldsa.Verify: %w`, err)
	}
	return jwsbb.Verify(pk, v.algName, payload, signature)
}

// mldsaAKPFields pulls the parameter set and the "pub" bytes out of an AKP
// jwk.Key, rejecting keys whose "alg" does not name the expected ML-DSA
// parameter set.
func mldsaAKPFields(k jwk.Key, params mldsa.Parameters) ([]byte, error) {
	if k.KeyType() != jwa.AKP() {
		return nil, fmt.Errorf(`expected AKP key type, got %s`, k.KeyType())
	}
	alg, ok := k.Algorithm()
	if !ok {
		return nil, fmt.Errorf(`AKP key is missing the required "alg" field`)
	}
	keyParams, err := mldsaParamsForAlg(alg.String())
	if err != nil {
		return nil, fmt.Errorf(`AKP key "alg" is not an ML-DSA variant: %w`, err)
	}
	if err := requireMLDSAParamsMatch(keyParams, params); err != nil {
		return nil, err
	}

	pubV, ok := k.Field(jwk.AKPPubKey)
	if !ok {
		return nil, fmt.Errorf(`AKP key does not contain the "pub" field`)
	}
	pubBytes, ok := pubV.([]byte)
	if !ok {
		return nil, fmt.Errorf(`AKP key "pub" field is %T, expected []byte`, pubV)
	}
	return pubBytes, nil
}

// mldsaPrivateKeyFrom accepts either a raw crypto/mldsa private key or an AKP
// jwk.Key holding one, and returns the private key for the expected parameter
// set.
func mldsaPrivateKeyFrom(key any, params mldsa.Parameters) (*mldsa.PrivateKey, error) {
	switch k := key.(type) {
	case *mldsa.PrivateKey:
		if err := requireMLDSAParamsMatch(k.PublicKey().Parameters(), params); err != nil {
			return nil, err
		}
		return k, nil
	case jwk.Key:
		pubBytes, err := mldsaAKPFields(k, params)
		if err != nil {
			return nil, err
		}

		privV, ok := k.Field(jwk.AKPPrivKey)
		if !ok {
			return nil, fmt.Errorf(`AKP key does not contain the "priv" field`)
		}
		privBytes, ok := privV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`AKP key "priv" field is %T, expected []byte`, privV)
		}

		sk, err := mldsa.NewPrivateKey(params, privBytes)
		if err != nil {
			return nil, fmt.Errorf(`failed to construct ML-DSA private key: %w`, err)
		}
		if !bytes.Equal(sk.PublicKey().Bytes(), pubBytes) {
			return nil, fmt.Errorf(`AKP key "pub" does not match the public key derived from "priv"`)
		}
		return sk, nil
	default:
		return nil, fmt.Errorf(`unsupported key type %T for ML-DSA signing`, key)
	}
}

// mldsaPublicKeyFrom accepts a raw crypto/mldsa key of either kind or an AKP
// jwk.Key, and returns the public key for the expected parameter set.
func mldsaPublicKeyFrom(key any, params mldsa.Parameters) (*mldsa.PublicKey, error) {
	switch k := key.(type) {
	case *mldsa.PublicKey:
		if err := requireMLDSAParamsMatch(k.Parameters(), params); err != nil {
			return nil, err
		}
		return k, nil
	case *mldsa.PrivateKey:
		pk := k.PublicKey()
		if err := requireMLDSAParamsMatch(pk.Parameters(), params); err != nil {
			return nil, err
		}
		return pk, nil
	case jwk.Key:
		pubBytes, err := mldsaAKPFields(k, params)
		if err != nil {
			return nil, err
		}
		pk, err := mldsa.NewPublicKey(params, pubBytes)
		if err != nil {
			return nil, fmt.Errorf(`failed to construct ML-DSA public key: %w`, err)
		}
		return pk, nil
	default:
		return nil, fmt.Errorf(`unsupported key type %T for ML-DSA verification`, key)
	}
}
