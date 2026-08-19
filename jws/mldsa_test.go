//go:build go1.27

package jws_test

import (
	"crypto"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
	"github.com/stretchr/testify/require"
)

func mldsaCases() []struct {
	name   string
	alg    jwa.SignatureAlgorithm
	params mldsa.Parameters
} {
	return []struct {
		name   string
		alg    jwa.SignatureAlgorithm
		params mldsa.Parameters
	}{
		{"ML-DSA-44", jwa.MLDSA44(), mldsa.MLDSA44()},
		{"ML-DSA-65", jwa.MLDSA65(), mldsa.MLDSA65()},
		{"ML-DSA-87", jwa.MLDSA87(), mldsa.MLDSA87()},
	}
}

func TestMLDSASignVerifyRawKey(t *testing.T) {
	t.Parallel()

	for _, tc := range mldsaCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			payload := []byte("Hello, post-quantum world!")

			sk, err := mldsa.GenerateKey(tc.params)
			require.NoError(t, err)

			signed, err := jws.Sign(payload, jws.WithKey(tc.alg, sk))
			require.NoError(t, err)

			verified, err := jws.Verify(signed, jws.WithKey(tc.alg, sk.PublicKey()))
			require.NoError(t, err)
			require.Equal(t, payload, verified)

			// A private key on the verify side must yield its public half.
			verified, err = jws.Verify(signed, jws.WithKey(tc.alg, sk))
			require.NoError(t, err)
			require.Equal(t, payload, verified)
		})
	}
}

func TestMLDSASignVerifyJWK(t *testing.T) {
	t.Parallel()

	for _, tc := range mldsaCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			payload := []byte("Hello, post-quantum world!")

			sk, err := mldsa.GenerateKey(tc.params)
			require.NoError(t, err)

			privJWK, err := jwk.Import[jwk.Key](sk)
			require.NoError(t, err)
			require.Equal(t, jwa.AKP(), privJWK.KeyType())

			signed, err := jws.Sign(payload, jws.WithKey(tc.alg, privJWK))
			require.NoError(t, err)

			pubJWK, err := privJWK.PublicKey()
			require.NoError(t, err)

			verified, err := jws.Verify(signed, jws.WithKey(tc.alg, pubJWK))
			require.NoError(t, err)
			require.Equal(t, payload, verified)
		})
	}
}

func TestMLDSAProtectedHeaderCarriesAlg(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	signed, err := jws.Sign([]byte("header check"), jws.WithKey(jwa.MLDSA65(), sk))
	require.NoError(t, err)

	msg, err := jws.Parse(signed)
	require.NoError(t, err)
	require.Len(t, msg.Signatures(), 1)

	alg, ok := msg.Signatures()[0].ProtectedHeaders().Algorithm()
	require.True(t, ok)
	require.Equal(t, "ML-DSA-65", alg.String())
}

func TestMLDSAVerifyRejectsWrongKey(t *testing.T) {
	t.Parallel()

	payload := []byte("cross-key test")

	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.MLDSA44(), sk))
	require.NoError(t, err)

	other, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	_, err = jws.Verify(signed, jws.WithKey(jwa.MLDSA44(), other.PublicKey()))
	require.Error(t, err)
}

// TestMLDSAParamSetConfusion covers algorithm/key confusion across the three
// parameter sets. crypto/mldsa binds the parameter set to the key object, so an
// ML-DSA-65 key verifies an ML-DSA-65 signature even when the caller asked for
// ML-DSA-44. Without an explicit cross-check between the supplied key and the
// algorithm's registered parameter set, a peer that reads the protected header
// to decide post-quantum security level can be misled about which parameter set
// actually signed the payload. Every entry point that takes a key and an
// algorithm has to reject the mismatch.
func TestMLDSAParamSetConfusion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		routeAlg jwa.SignatureAlgorithm
		keyGen   mldsa.Parameters
	}{
		{"ML-DSA-65-as-ML-DSA-44", jwa.MLDSA44(), mldsa.MLDSA65()},
		{"ML-DSA-87-as-ML-DSA-44", jwa.MLDSA44(), mldsa.MLDSA87()},
		{"ML-DSA-87-as-ML-DSA-65", jwa.MLDSA65(), mldsa.MLDSA87()},
		{"ML-DSA-44-as-ML-DSA-65", jwa.MLDSA65(), mldsa.MLDSA44()},
		{"ML-DSA-44-as-ML-DSA-87", jwa.MLDSA87(), mldsa.MLDSA44()},
		{"ML-DSA-65-as-ML-DSA-87", jwa.MLDSA87(), mldsa.MLDSA65()},
	}

	payload := []byte("parameter-set confusion reproducer")

	for _, tc := range cases {
		t.Run("jws.Sign/"+tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)
			_, err = jws.Sign(payload, jws.WithKey(tc.routeAlg, sk))
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
		})

		t.Run("jwsbb.Sign/"+tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)
			_, err = jwsbb.Sign(sk, tc.routeAlg.String(), payload, nil)
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
		})

		t.Run("jws.Sign/JWK/"+tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)

			privJWK, err := jwk.Import[jwk.Key](sk)
			require.NoError(t, err)

			_, err = jws.Sign(payload, jws.WithKey(tc.routeAlg, privJWK))
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
			// The mismatch must be caught before key construction, so the
			// error names the real cause rather than a downstream symptom.
			require.NotContains(t, err.Error(), "failed to construct ML-DSA private key")
		})

		t.Run("jws.Verify/"+tc.name, func(t *testing.T) {
			t.Parallel()
			// Build the forgery independently of jws.Sign so a genuine
			// signature reaches the verifier even with the sign-side check in
			// place: the header claims routeAlg while the signature is a real
			// one made under the other parameter set.
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)

			forged := forgeMLDSACompactJWS(t, sk, tc.routeAlg.String(), payload)

			_, err = jws.Verify(forged, jws.WithKey(tc.routeAlg, sk.PublicKey()))
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
		})

		t.Run("jws.Verify/JWK/"+tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)

			pubJWK, err := jwk.Import[jwk.Key](sk.PublicKey())
			require.NoError(t, err)

			forged := forgeMLDSACompactJWS(t, sk, tc.routeAlg.String(), payload)

			_, err = jws.Verify(forged, jws.WithKey(tc.routeAlg, pubJWK))
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
			require.NotContains(t, err.Error(), "failed to construct ML-DSA public key")
		})

		t.Run("jwsbb.Verify/"+tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)

			signingInput := []byte("direct-dsig-" + tc.name)
			sig, err := sk.Sign(nil, signingInput, nil)
			require.NoError(t, err)

			err = jwsbb.Verify(sk.PublicKey(), tc.routeAlg.String(), signingInput, sig)
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
		})
	}
}

// forgeMLDSACompactJWS assembles a compact JWS by hand, signing with
// crypto/mldsa directly so the signature is valid under sk's own parameter set
// no matter what algHeader claims.
func forgeMLDSACompactJWS(t *testing.T, sk *mldsa.PrivateKey, algHeader string, payload []byte) []byte {
	t.Helper()

	hdr, err := json.Marshal(map[string]string{"alg": algHeader})
	require.NoError(t, err)

	b64 := base64.RawURLEncoding
	encHdr := b64.EncodeToString(hdr)
	encPayload := b64.EncodeToString(payload)

	sig, err := sk.Sign(nil, []byte(encHdr+"."+encPayload), nil)
	require.NoError(t, err)

	return []byte(encHdr + "." + encPayload + "." + b64.EncodeToString(sig))
}

// TestMLDSASignerOptsTypeMismatch covers a non-nil crypto.SignerOpts whose
// concrete type is not *mldsa.Options. Coercing it to nil would let a caller
// believe their Context was in force while the signature was actually made with
// an empty context, so the mismatch has to be an error.
func TestMLDSASignerOptsTypeMismatch(t *testing.T) {
	t.Parallel()

	const alg = "ML-DSA-65"

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	pk := sk.PublicKey()

	msg := []byte("mldsa opts type mismatch")

	t.Run("Sign rejects foreign opts type", func(t *testing.T) {
		t.Parallel()
		_, err := jwsbb.SignWithOpts(sk, alg, msg, crypto.SHA256, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "expected *mldsa.Options")
	})

	t.Run("Verify rejects foreign opts type", func(t *testing.T) {
		t.Parallel()
		sig, err := jwsbb.Sign(sk, alg, msg, nil)
		require.NoError(t, err)

		err = jwsbb.VerifyWithOpts(pk, alg, msg, sig, crypto.SHA256)
		require.Error(t, err)
		require.ErrorContains(t, err, "expected *mldsa.Options")
	})

	t.Run("nil opts is accepted", func(t *testing.T) {
		t.Parallel()
		sig, err := jwsbb.SignWithOpts(sk, alg, msg, nil, nil)
		require.NoError(t, err)
		require.NoError(t, jwsbb.VerifyWithOpts(pk, alg, msg, sig, nil))
	})

	t.Run("Context is honored on both sides", func(t *testing.T) {
		t.Parallel()
		opts := &mldsa.Options{Context: "jwx-test-ctx"}
		sig, err := jwsbb.SignWithOpts(sk, alg, msg, opts, nil)
		require.NoError(t, err)
		require.NoError(t, jwsbb.VerifyWithOpts(pk, alg, msg, sig, opts))

		// A different context must not verify, or the context would be
		// decorative rather than binding.
		wrong := &mldsa.Options{Context: "different"}
		require.Error(t, jwsbb.VerifyWithOpts(pk, alg, msg, sig, wrong))
	})
}

// TestMLDSAJWKAlgValidation covers AKP JWKs whose "alg" is missing or names
// something other than an ML-DSA parameter set. The 32-byte seed is the same
// length for all three variants, so length tells the signer nothing; without
// the "alg" check, whoever controls the JWK chooses the parameter set the
// signature is made under.
func TestMLDSAJWKAlgValidation(t *testing.T) {
	t.Parallel()

	payload := []byte("alg validation")

	newPrivJWK := func(t *testing.T) jwk.Key {
		t.Helper()
		sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](sk)
		require.NoError(t, err)
		return privJWK
	}

	t.Run("Sign rejects a JWK with no alg", func(t *testing.T) {
		t.Parallel()
		privJWK := newPrivJWK(t)
		require.NoError(t, privJWK.Remove(jwk.AlgorithmKey))

		_, err := jws.Sign(payload, jws.WithKey(jwa.MLDSA65(), privJWK))
		require.Error(t, err)
	})

	t.Run("Verify rejects a JWK with no alg", func(t *testing.T) {
		t.Parallel()
		privJWK := newPrivJWK(t)
		signed, err := jws.Sign(payload, jws.WithKey(jwa.MLDSA65(), privJWK))
		require.NoError(t, err)

		pubJWK, err := privJWK.PublicKey()
		require.NoError(t, err)
		require.NoError(t, pubJWK.Remove(jwk.AlgorithmKey))

		_, err = jws.Verify(signed, jws.WithKey(jwa.MLDSA65(), pubJWK))
		require.Error(t, err)
	})

	t.Run("Sign rejects a JWK whose alg is not ML-DSA", func(t *testing.T) {
		t.Parallel()
		privJWK := newPrivJWK(t)
		// RS256 is a registered algorithm but not an ML-DSA parameter set, so
		// the lookup failure must be treated as "the JWK lied", not as
		// "no further check needed".
		require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.RS256()))

		_, err := jws.Sign(payload, jws.WithKey(jwa.MLDSA65(), privJWK))
		require.Error(t, err)
	})

	t.Run("Verify rejects a JWK whose alg is not ML-DSA", func(t *testing.T) {
		t.Parallel()
		privJWK := newPrivJWK(t)
		signed, err := jws.Sign(payload, jws.WithKey(jwa.MLDSA65(), privJWK))
		require.NoError(t, err)

		pubJWK, err := privJWK.PublicKey()
		require.NoError(t, err)
		require.NoError(t, pubJWK.Set(jwk.AlgorithmKey, jwa.RS256()))

		_, err = jws.Verify(signed, jws.WithKey(jwa.MLDSA65(), pubJWK))
		require.Error(t, err)
	})
}

// TestMLDSASignRejectsPubMismatch covers an AKP JWK whose "pub" disagrees with
// the key derived from "priv". Signing anyway would produce a signature under
// the seed-derived key that no relying party trusting the JWK's "pub" could
// verify.
func TestMLDSASignRejectsPubMismatch(t *testing.T) {
	t.Parallel()

	skA, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	skB, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	privJWK, err := jwk.Import[jwk.Key](skA)
	require.NoError(t, err)
	require.NoError(t, privJWK.Set(jwk.AKPPubKey, skB.PublicKey().Bytes()))

	_, err = jws.Sign([]byte("pub mismatch"), jws.WithKey(jwa.MLDSA65(), privJWK))
	require.Error(t, err)
	require.ErrorContains(t, err, `does not match the public key derived from "priv"`)
}
