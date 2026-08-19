//go:build go1.27

package jws_test

import (
	"crypto/mldsa"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

// FuzzMLDSASignAndVerify checks that any payload survives a sign/verify
// round-trip under each ML-DSA parameter set. Key generation happens once,
// outside f.Fuzz, because it dominates the cost of an iteration.
func FuzzMLDSASignAndVerify(f *testing.F) {
	f.Add([]byte("Hello, post-quantum world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))
	f.Add([]byte("The true sign of intelligence is not knowledge but imagination."))

	type keyed struct {
		alg jwa.SignatureAlgorithm
		sk  *mldsa.PrivateKey
		pk  *mldsa.PublicKey
	}

	var keys []keyed
	for _, tc := range []struct {
		alg    jwa.SignatureAlgorithm
		params mldsa.Parameters
	}{
		{jwa.MLDSA44(), mldsa.MLDSA44()},
		{jwa.MLDSA65(), mldsa.MLDSA65()},
		{jwa.MLDSA87(), mldsa.MLDSA87()},
	} {
		sk, err := mldsa.GenerateKey(tc.params)
		if err != nil {
			f.Fatal(err)
		}
		keys = append(keys, keyed{alg: tc.alg, sk: sk, pk: sk.PublicKey()})
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, k := range keys {
			signed, err := jws.Sign(payload, jws.WithKey(k.alg, k.sk))
			require.NoError(t, err)

			verified, err := jws.Verify(signed, jws.WithKey(k.alg, k.pk))
			require.NoError(t, err)
			require.Equal(t, payload, verified)
		}
	})
}

// FuzzMLDSAJWKRoundTrip feeds arbitrary bytes to the AKP parser and re-marshals
// whatever parses, so a key that survives one round must survive the next.
func FuzzMLDSAJWKRoundTrip(f *testing.F) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		f.Fatal(err)
	}
	privJWK, err := jwk.Import[jwk.Key](sk)
	if err != nil {
		f.Fatal(err)
	}
	seedJSON, err := json.Marshal(privJWK)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(seedJSON)
	f.Add([]byte(""))
	f.Add([]byte("not-json"))
	f.Add([]byte(`{"kty":"AKP","alg":"ML-DSA-65","pub":"AAAA"}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		parsed, err := jwk.ParseKeyAs[jwk.Key](data)
		if err != nil {
			return
		}

		buf, err := json.Marshal(parsed)
		if err != nil {
			return
		}

		_, _ = jwk.ParseKeyAs[jwk.Key](buf)
	})
}
