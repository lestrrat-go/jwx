package jws_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

func TestVerifyDetached(t *testing.T) {
	payload := []byte("The true sign of intelligence is not knowledge but imagination.")

	t.Run("RoundTrip", func(t *testing.T) {
		t.Run("HS256", func(t *testing.T) {
			key := jwxtest.GenerateSymmetricKey()
			signed, err := jws.Sign(nil, jws.WithKey(jwa.HS256(), key), jws.WithDetachedPayload(payload))
			require.NoError(t, err, `jws.Sign should succeed`)

			err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
			require.NoError(t, err, `jws.VerifyDetached should succeed`)
		})
		t.Run("RS256", func(t *testing.T) {
			privkey, err := jwxtest.GenerateRsaKey()
			require.NoError(t, err, `key generation should succeed`)

			signed, err := jws.Sign(nil, jws.WithKey(jwa.RS256(), privkey), jws.WithDetachedPayload(payload))
			require.NoError(t, err, `jws.Sign should succeed`)

			err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.RS256(), &privkey.PublicKey))
			require.NoError(t, err, `jws.VerifyDetached should succeed`)
		})
		t.Run("PS256", func(t *testing.T) {
			privkey, err := jwxtest.GenerateRsaKey()
			require.NoError(t, err, `key generation should succeed`)

			signed, err := jws.Sign(nil, jws.WithKey(jwa.PS256(), privkey), jws.WithDetachedPayload(payload))
			require.NoError(t, err, `jws.Sign should succeed`)

			err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.PS256(), &privkey.PublicKey))
			require.NoError(t, err, `jws.VerifyDetached should succeed`)
		})
		t.Run("ES256", func(t *testing.T) {
			privkey, err := jwxtest.GenerateEcdsaKey(jwa.P256())
			require.NoError(t, err, `key generation should succeed`)

			signed, err := jws.Sign(nil, jws.WithKey(jwa.ES256(), privkey), jws.WithDetachedPayload(payload))
			require.NoError(t, err, `jws.Sign should succeed`)

			err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.ES256(), &privkey.PublicKey))
			require.NoError(t, err, `jws.VerifyDetached should succeed`)
		})
	})

	t.Run("EdDSA returns error", func(t *testing.T) {
		privkey, err := jwxtest.GenerateEd25519Key()
		require.NoError(t, err, `key generation should succeed`)

		signed, err := jws.Sign(nil, jws.WithKey(jwa.EdDSA(), privkey), jws.WithDetachedPayload(payload))
		require.NoError(t, err, `jws.Sign should succeed`)

		err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.EdDSA(), privkey.Public()))
		require.Error(t, err, `jws.VerifyDetached should fail for EdDSA`)
	})

	t.Run("b64=false", func(t *testing.T) {
		key := jwxtest.GenerateSymmetricKey()

		hdrs := jws.NewHeaders()
		hdrs.Set("b64", false)
		hdrs.Set("crit", "b64")

		signed, err := jws.Sign(nil, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)), jws.WithDetachedPayload(payload))
		require.NoError(t, err, `jws.Sign should succeed`)

		err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jws.VerifyDetached with b64=false should succeed`)
	})

	t.Run("Large payload", func(t *testing.T) {
		const size = 10 * 1024 * 1024
		largePayload := make([]byte, size)
		_, err := rand.Read(largePayload)
		require.NoError(t, err, `rand.Read should succeed`)

		privkey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `key generation should succeed`)

		signed, err := jws.Sign(nil, jws.WithKey(jwa.RS256(), privkey), jws.WithDetachedPayload(largePayload))
		require.NoError(t, err, `jws.Sign should succeed`)

		err = jws.VerifyDetached(signed, bytes.NewReader(largePayload), jws.WithKey(jwa.RS256(), &privkey.PublicKey))
		require.NoError(t, err, `jws.VerifyDetached with large payload should succeed`)
	})

	t.Run("IO error mid-stream", func(t *testing.T) {
		privkey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `key generation should succeed`)

		signed, err := jws.Sign(nil, jws.WithKey(jwa.RS256(), privkey), jws.WithDetachedPayload(payload))
		require.NoError(t, err, `jws.Sign should succeed`)

		errReader := &failingReader{
			data:    payload,
			failAt:  10,
			failErr: fmt.Errorf("simulated I/O error"),
		}

		err = jws.VerifyDetached(signed, errReader, jws.WithKey(jwa.RS256(), &privkey.PublicKey))
		require.Error(t, err, `jws.VerifyDetached should fail on I/O error`)
	})

	t.Run("Wrong key returns error", func(t *testing.T) {
		privkey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `key generation should succeed`)

		wrongKey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `key generation should succeed`)

		signed, err := jws.Sign(nil, jws.WithKey(jwa.RS256(), privkey), jws.WithDetachedPayload(payload))
		require.NoError(t, err, `jws.Sign should succeed`)

		err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.RS256(), &wrongKey.PublicKey))
		require.Error(t, err, `jws.VerifyDetached with wrong key should fail`)
		require.True(t, errors.Is(err, jws.VerifyError()), `error should be a VerifyError`)
	})

	t.Run("Cross-verify with jws.Verify", func(t *testing.T) {
		algorithms := []struct {
			alg     jwa.SignatureAlgorithm
			privkey any
			pubkey  any
		}{
			func() struct {
				alg     jwa.SignatureAlgorithm
				privkey any
				pubkey  any
			} {
				key := jwxtest.GenerateSymmetricKey()
				return struct {
					alg     jwa.SignatureAlgorithm
					privkey any
					pubkey  any
				}{jwa.HS256(), key, key}
			}(),
			func() struct {
				alg     jwa.SignatureAlgorithm
				privkey any
				pubkey  any
			} {
				key, _ := jwxtest.GenerateRsaKey()
				return struct {
					alg     jwa.SignatureAlgorithm
					privkey any
					pubkey  any
				}{jwa.RS256(), key, &key.PublicKey}
			}(),
			func() struct {
				alg     jwa.SignatureAlgorithm
				privkey any
				pubkey  any
			} {
				key, _ := jwxtest.GenerateEcdsaKey(jwa.P256())
				return struct {
					alg     jwa.SignatureAlgorithm
					privkey any
					pubkey  any
				}{jwa.ES256(), key, &key.PublicKey}
			}(),
		}

		for _, tc := range algorithms {
			t.Run(tc.alg.String(), func(t *testing.T) {
				signed, err := jws.Sign(nil, jws.WithKey(tc.alg, tc.privkey), jws.WithDetachedPayload(payload))
				require.NoError(t, err, `jws.Sign should succeed`)

				_, err = jws.Verify(signed, jws.WithKey(tc.alg, tc.pubkey), jws.WithDetachedPayload(payload))
				require.NoError(t, err, `jws.Verify should succeed`)

				err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(tc.alg, tc.pubkey))
				require.NoError(t, err, `jws.VerifyDetached should succeed`)
			})
		}
	})

	t.Run("Rejects WithDetachedPayload option", func(t *testing.T) {
		key := jwxtest.GenerateSymmetricKey()
		signed, err := jws.Sign(nil, jws.WithKey(jwa.HS256(), key), jws.WithDetachedPayload(payload))
		require.NoError(t, err)

		err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key), jws.WithDetachedPayload(payload))
		require.Error(t, err, `should reject WithDetachedPayload`)
	})

	t.Run("Rejects no key", func(t *testing.T) {
		err := jws.VerifyDetached([]byte("eyJhbGciOiJIUzI1NiJ9..sig"), bytes.NewReader(payload))
		require.Error(t, err, `should reject missing key`)
	})

	t.Run("Rejects multiple keys", func(t *testing.T) {
		key1 := jwxtest.GenerateSymmetricKey()
		key2 := jwxtest.GenerateSymmetricKey()
		signed, err := jws.Sign(nil, jws.WithKey(jwa.HS256(), key1), jws.WithDetachedPayload(payload))
		require.NoError(t, err)

		err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key1), jws.WithKey(jwa.HS256(), key2))
		require.Error(t, err, `should reject multiple keys`)
	})
}

// failingReader reads from data up to failAt bytes, then returns failErr.
type failingReader struct {
	data    []byte
	pos     int
	failAt  int
	failErr error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.pos >= r.failAt {
		return 0, r.failErr
	}
	remaining := min(r.failAt-r.pos, len(p), len(r.data)-r.pos)
	n := copy(p, r.data[r.pos:r.pos+remaining])
	r.pos += n
	if r.pos >= r.failAt {
		return n, r.failErr
	}
	return n, nil
}
