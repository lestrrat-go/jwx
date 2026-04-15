package jws_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

func TestSignDetached(t *testing.T) {
	payload := []byte("The true sign of intelligence is not knowledge but imagination.")

	t.Run("RoundTrip", func(t *testing.T) {
		t.Run("HS256", func(t *testing.T) {
			key := jwxtest.GenerateSymmetricKey()

			signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
			require.NoError(t, err, `jws.SignDetached should succeed`)

			err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
			require.NoError(t, err, `jws.VerifyDetached should succeed`)

			_, err = jws.Verify(signed, jws.WithKey(jwa.HS256(), key), jws.WithDetachedPayload(payload))
			require.NoError(t, err, `jws.Verify with WithDetachedPayload should succeed`)
		})
		t.Run("RS256", func(t *testing.T) {
			privkey, err := jwxtest.GenerateRsaKey()
			require.NoError(t, err, `key generation should succeed`)

			signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.RS256(), privkey))
			require.NoError(t, err, `jws.SignDetached should succeed`)

			err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.RS256(), &privkey.PublicKey))
			require.NoError(t, err, `jws.VerifyDetached should succeed`)

			_, err = jws.Verify(signed, jws.WithKey(jwa.RS256(), &privkey.PublicKey), jws.WithDetachedPayload(payload))
			require.NoError(t, err, `jws.Verify with WithDetachedPayload should succeed`)
		})
		t.Run("PS256", func(t *testing.T) {
			privkey, err := jwxtest.GenerateRsaKey()
			require.NoError(t, err, `key generation should succeed`)

			signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.PS256(), privkey))
			require.NoError(t, err, `jws.SignDetached should succeed`)

			err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.PS256(), &privkey.PublicKey))
			require.NoError(t, err, `jws.VerifyDetached should succeed`)

			_, err = jws.Verify(signed, jws.WithKey(jwa.PS256(), &privkey.PublicKey), jws.WithDetachedPayload(payload))
			require.NoError(t, err, `jws.Verify with WithDetachedPayload should succeed`)
		})
		t.Run("ES256", func(t *testing.T) {
			privkey, err := jwxtest.GenerateEcdsaKey(jwa.P256())
			require.NoError(t, err, `key generation should succeed`)

			signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.ES256(), privkey))
			require.NoError(t, err, `jws.SignDetached should succeed`)

			err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.ES256(), &privkey.PublicKey))
			require.NoError(t, err, `jws.VerifyDetached should succeed`)

			_, err = jws.Verify(signed, jws.WithKey(jwa.ES256(), &privkey.PublicKey), jws.WithDetachedPayload(payload))
			require.NoError(t, err, `jws.Verify with WithDetachedPayload should succeed`)
		})
	})

	t.Run("EdDSA returns error", func(t *testing.T) {
		privkey, err := jwxtest.GenerateEd25519Key()
		require.NoError(t, err, `key generation should succeed`)

		_, err = jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.EdDSA(), privkey))
		require.Error(t, err, `jws.SignDetached should fail for EdDSA`)
	})

	t.Run("b64=false", func(t *testing.T) {
		key := jwxtest.GenerateSymmetricKey()

		hdrs := jws.NewHeaders()
		hdrs.Set("b64", false)
		hdrs.Set("crit", "b64")

		signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)))
		require.NoError(t, err, `jws.SignDetached should succeed`)

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

		signed, err := jws.SignDetached(bytes.NewReader(largePayload), jws.WithKey(jwa.RS256(), privkey))
		require.NoError(t, err, `jws.SignDetached should succeed`)

		err = jws.VerifyDetached(signed, bytes.NewReader(largePayload), jws.WithKey(jwa.RS256(), &privkey.PublicKey))
		require.NoError(t, err, `jws.VerifyDetached with large payload should succeed`)
	})

	t.Run("IO error mid-stream", func(t *testing.T) {
		privkey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `key generation should succeed`)

		errReader := &failingReader{
			data:    payload,
			failAt:  10,
			failErr: fmt.Errorf("simulated I/O error"),
		}

		_, err = jws.SignDetached(errReader, jws.WithKey(jwa.RS256(), privkey))
		require.Error(t, err, `jws.SignDetached should fail on I/O error`)
	})

	t.Run("Wrong key fails verification", func(t *testing.T) {
		privkey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `key generation should succeed`)

		wrongKey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `key generation should succeed`)

		signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.RS256(), privkey))
		require.NoError(t, err, `jws.SignDetached should succeed`)

		err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.RS256(), &wrongKey.PublicKey))
		require.Error(t, err, `jws.VerifyDetached with wrong key should fail`)
		require.True(t, errors.Is(err, jws.VerifyError()), `error should be a VerifyError`)
		require.True(t, errors.Is(err, jws.VerificationError()), `error should be a VerificationError`)
	})

	t.Run("Cross-verify with jws.Sign", func(t *testing.T) {
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
				// Sign with jws.Sign, verify with jws.VerifyDetached
				signedTraditional, err := jws.Sign(nil, jws.WithKey(tc.alg, tc.privkey), jws.WithDetachedPayload(payload))
				require.NoError(t, err, `jws.Sign should succeed`)

				err = jws.VerifyDetached(signedTraditional, bytes.NewReader(payload), jws.WithKey(tc.alg, tc.pubkey))
				require.NoError(t, err, `jws.VerifyDetached should verify jws.Sign output`)

				// Sign with jws.SignDetached, verify with jws.Verify
				signedStreaming, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(tc.alg, tc.privkey))
				require.NoError(t, err, `jws.SignDetached should succeed`)

				_, err = jws.Verify(signedStreaming, jws.WithKey(tc.alg, tc.pubkey), jws.WithDetachedPayload(payload))
				require.NoError(t, err, `jws.Verify should verify jws.SignDetached output`)
			})
		}
	})

	t.Run("Rejects WithDetachedPayload option", func(t *testing.T) {
		key := jwxtest.GenerateSymmetricKey()
		_, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key), jws.WithDetachedPayload(payload))
		require.Error(t, err, `should reject WithDetachedPayload`)
	})

	t.Run("Rejects no key", func(t *testing.T) {
		_, err := jws.SignDetached(bytes.NewReader(payload))
		require.Error(t, err, `should reject missing key`)
	})

	t.Run("Rejects multiple keys", func(t *testing.T) {
		key1 := jwxtest.GenerateSymmetricKey()
		key2 := jwxtest.GenerateSymmetricKey()
		_, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key1), jws.WithKey(jwa.HS256(), key2))
		require.Error(t, err, `should reject multiple keys`)
	})

	t.Run("jwk.Key input", func(t *testing.T) {
		privkey, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err, `key generation should succeed`)

		pubkey, err := jwk.PublicKeyOf(privkey)
		require.NoError(t, err, `public key extraction should succeed`)

		signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.RS256(), privkey))
		require.NoError(t, err, `jws.SignDetached with jwk.Key should succeed`)

		err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.RS256(), pubkey))
		require.NoError(t, err, `jws.VerifyDetached with jwk.Key should succeed`)
	})

	t.Run("WithCompact is accepted as no-op", func(t *testing.T) {
		key := jwxtest.GenerateSymmetricKey()

		plain, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err)

		explicit, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key), jws.WithCompact())
		require.NoError(t, err)

		require.Equal(t, string(plain), string(explicit), `WithCompact should produce byte-identical output to default`)
	})

	t.Run("JSON output round-trip", func(t *testing.T) {
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
				k := jwxtest.GenerateSymmetricKey()
				return struct {
					alg     jwa.SignatureAlgorithm
					privkey any
					pubkey  any
				}{jwa.HS256(), k, k}
			}(),
			func() struct {
				alg     jwa.SignatureAlgorithm
				privkey any
				pubkey  any
			} {
				k, _ := jwxtest.GenerateRsaKey()
				return struct {
					alg     jwa.SignatureAlgorithm
					privkey any
					pubkey  any
				}{jwa.RS256(), k, &k.PublicKey}
			}(),
			func() struct {
				alg     jwa.SignatureAlgorithm
				privkey any
				pubkey  any
			} {
				k, _ := jwxtest.GenerateEcdsaKey(jwa.P256())
				return struct {
					alg     jwa.SignatureAlgorithm
					privkey any
					pubkey  any
				}{jwa.ES256(), k, &k.PublicKey}
			}(),
		}

		for _, tc := range algorithms {
			t.Run(tc.alg.String(), func(t *testing.T) {
				signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(tc.alg, tc.privkey), jws.WithJSON())
				require.NoError(t, err, `jws.SignDetached with WithJSON should succeed`)
				require.True(t, bytes.HasPrefix(bytes.TrimSpace(signed), []byte{'{'}), `output should begin with "{"`)

				err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(tc.alg, tc.pubkey))
				require.NoError(t, err, `jws.VerifyDetached should auto-detect JSON input`)

				err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(tc.alg, tc.pubkey), jws.WithJSON())
				require.NoError(t, err, `jws.VerifyDetached with explicit WithJSON should succeed`)
			})
		}
	})

	t.Run("JSON output omits payload member (RFC 7515 App F)", func(t *testing.T) {
		key := jwxtest.GenerateSymmetricKey()

		signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key), jws.WithJSON())
		require.NoError(t, err)

		var m map[string]any
		require.NoError(t, json.Unmarshal(signed, &m))

		_, hasPayload := m["payload"]
		require.False(t, hasPayload, `JSON output must not contain a "payload" member per RFC 7515 Appendix F`)

		_, hasProtected := m["protected"]
		require.True(t, hasProtected, `JSON output must contain a "protected" member`)

		_, hasSignature := m["signature"]
		require.True(t, hasSignature, `JSON output must contain a "signature" member`)

		_, hasHeader := m["header"]
		require.False(t, hasHeader, `JSON output must not contain a "header" member when no unprotected headers are set`)
	})

	t.Run("JSON pretty output", func(t *testing.T) {
		key := jwxtest.GenerateSymmetricKey()

		signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key), jws.WithJSON(jws.WithPretty(true)))
		require.NoError(t, err)

		require.True(t, strings.Contains(string(signed), "\n"), `pretty JSON should contain newlines`)

		// Still verifies correctly after pretty formatting
		err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err)
	})

	t.Run("JSON with unprotected header", func(t *testing.T) {
		key := jwxtest.GenerateSymmetricKey()

		public := jws.NewHeaders()
		require.NoError(t, public.Set("kid", "unprotected-kid"))

		signed, err := jws.SignDetached(
			bytes.NewReader(payload),
			jws.WithKey(jwa.HS256(), key, jws.WithPublicHeaders(public)),
			jws.WithJSON(),
		)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(signed, &m))

		headerJSON, ok := m["header"]
		require.True(t, ok, `JSON output should contain "header" when unprotected headers are set`)
		require.Contains(t, string(headerJSON), `"kid":"unprotected-kid"`, `unprotected header should appear under "header"`)

		// Verify the signature is still valid.
		err = jws.VerifyDetached(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err)
	})

	t.Run("JSON output verifiable by jws.Verify", func(t *testing.T) {
		privkey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err)

		signed, err := jws.SignDetached(bytes.NewReader(payload), jws.WithKey(jwa.RS256(), privkey), jws.WithJSON())
		require.NoError(t, err)

		// The non-streaming Verify should accept the streaming JSON output
		// when given the original payload via WithDetachedPayload.
		_, err = jws.Verify(signed, jws.WithKey(jwa.RS256(), &privkey.PublicKey), jws.WithDetachedPayload(payload))
		require.NoError(t, err, `jws.Verify should accept SignDetached+WithJSON output`)
	})
}
