package jws_test

import (
	"bytes"
	"context"
	"crypto/rand"
	stdbase64 "encoding/base64"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

type streamingDetachedAlgCase struct {
	name      string
	alg       jwa.SignatureAlgorithm
	signKey   any
	verifyKey any
}

func streamingDetachedAlgCases(t *testing.T) []streamingDetachedAlgCase {
	t.Helper()

	symmetricKey, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	rsaKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	rsaPub, err := jwk.PublicKeyOf(rsaKey)
	require.NoError(t, err)

	ecdsaKey, err := jwxtest.GenerateEcdsaJwk(jwa.P256())
	require.NoError(t, err)
	ecdsaPub, err := jwk.PublicKeyOf(ecdsaKey)
	require.NoError(t, err)

	return []streamingDetachedAlgCase{
		{name: "HS256", alg: jwa.HS256(), signKey: symmetricKey, verifyKey: symmetricKey},
		{name: "RS256", alg: jwa.RS256(), signKey: rsaKey, verifyKey: rsaPub},
		{name: "PS256", alg: jwa.PS256(), signKey: rsaKey, verifyKey: rsaPub},
		{name: "ES256", alg: jwa.ES256(), signKey: ecdsaKey, verifyKey: ecdsaPub},
	}
}

func TestStreamingDetachedCompactRoundTrip(t *testing.T) {
	t.Parallel()

	payload := []byte(`payload.with.periods and spaces`)

	for _, tc := range streamingDetachedAlgCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			signed, err := jws.Sign(nil,
				jws.WithKey(tc.alg, tc.signKey),
				jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
			)
			require.NoError(t, err)
			require.Contains(t, string(signed), "..")

			_, err = jws.Verify(signed,
				jws.WithKey(tc.alg, tc.verifyKey),
				jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
			)
			require.NoError(t, err)
		})
	}
}

func TestStreamingDetachedJSONRoundTrip(t *testing.T) {
	t.Parallel()

	payload := []byte(`reader-json-payload`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.Sign(nil,
		jws.WithJSON(),
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)
	require.NotContains(t, string(signed), `"payload"`)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)
}

// TestStreamingDetachedVerifyReturnsNonNilEmptyPayload locks in the
// sentinel contract that jws.Verify with WithDetachedPayloadReader returns
// a non-nil, zero-length []byte on success. The payload was streamed from
// the caller, not extracted from the envelope — so there are no bytes to
// return — but returning a nil slice would be indistinguishable from
// "ignored return value" and set up silent-logic bugs in callers that
// check len(payload)==0.
func TestStreamingDetachedVerifyReturnsNonNilEmptyPayload(t *testing.T) {
	t.Parallel()

	payload := []byte(`sentinel-return-payload`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)

	got, err := jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)
	require.NotNil(t, got, "streaming Verify must return a non-nil []byte on success so callers can distinguish it from an ignored return value")
	require.Empty(t, got, "streaming Verify has no payload bytes to hand back")
}

func TestStreamingDetachedKeyUsed(t *testing.T) {
	t.Parallel()

	payload := []byte(`key-used`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)

	var used any
	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithKeyUsed(&used),
	)
	require.NoError(t, err)
	require.Same(t, key, used)
}

func TestStreamingDetachedCritAutoAllowsB64(t *testing.T) {
	t.Parallel()

	payload := []byte(`raw.payload.with.periods`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	protected := jws.NewHeaders()
	require.NoError(t, protected.Set("b64", false))
	require.NoError(t, protected.Set(jws.CriticalKey, []string{"b64"}))

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(protected)),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)
}

func TestStreamingDetachedBase64EncoderHonored(t *testing.T) {
	t.Parallel()

	payload := []byte(`padded-reader-encoding`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	// encoding/base64.URLEncoding satisfies Base64StreamEncoder (it has
	// NewEncoder), so the streaming path accepts it. Round-tripping
	// through the same encoder verifies end-to-end.
	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithBase64Encoder(stdbase64.URLEncoding),
	)
	require.NoError(t, err)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithBase64Encoder(stdbase64.URLEncoding),
	)
	require.NoError(t, err)
}

// nonStreamEncoder wraps encoding/base64.Encoding but hides the
// NewEncoder method by redeclaring only the required Encoder surface.
// This simulates a third-party encoder that only satisfies the basic
// Base64Encoder interface.
type nonStreamEncoder struct {
	enc *stdbase64.Encoding
}

func (e nonStreamEncoder) Encode(dst, src []byte)           { e.enc.Encode(dst, src) }
func (e nonStreamEncoder) EncodedLen(n int) int             { return e.enc.EncodedLen(n) }
func (e nonStreamEncoder) EncodeToString(src []byte) string { return e.enc.EncodeToString(src) }
func (e nonStreamEncoder) AppendEncode(dst, src []byte) []byte {
	return e.enc.AppendEncode(dst, src)
}

func TestStreamingDetachedRejectsNonStreamEncoder(t *testing.T) {
	t.Parallel()

	payload := []byte(`non-stream-encoder`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	encoder := nonStreamEncoder{enc: stdbase64.RawURLEncoding}

	_, err = jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithBase64Encoder(encoder),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, `jws.WithBase64Encoder`)
	require.ErrorContains(t, err, `Install a stream-capable encoder`)

	// Sign a compact JWS normally so we have something to feed Verify.
	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithBase64Encoder(encoder),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, `jws.WithBase64Encoder`)
	require.ErrorContains(t, err, `Install a stream-capable encoder`)
}

func TestStreamingDetachedRejectsConflictingOptions(t *testing.T) {
	t.Parallel()

	payload := []byte(`conflict-options`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	t.Run("Sign rejects combined detached payload and reader", func(t *testing.T) {
		t.Parallel()

		_, err := jws.Sign(nil,
			jws.WithKey(jwa.HS256(), key),
			jws.WithDetachedPayload(payload),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.Error(t, err)
		require.ErrorContains(t, err, `mutually exclusive`)
	})

	t.Run("Verify rejects combined detached payload and reader", func(t *testing.T) {
		t.Parallel()

		signed, err := jws.Sign(nil, jws.WithKey(jwa.HS256(), key), jws.WithDetachedPayload(payload))
		require.NoError(t, err)

		_, err = jws.Verify(signed,
			jws.WithKey(jwa.HS256(), key),
			jws.WithDetachedPayload(payload),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.Error(t, err)
		require.ErrorContains(t, err, `mutually exclusive`)
	})

	t.Run("Sign rejects non-nil payload with reader", func(t *testing.T) {
		t.Parallel()

		_, err := jws.Sign(payload,
			jws.WithKey(jwa.HS256(), key),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.Error(t, err)
		require.ErrorContains(t, err, `first argument to jws.Sign() must be nil`)
	})

	t.Run("Sign rejects insecure no-signature", func(t *testing.T) {
		t.Parallel()

		_, err := jws.Sign(nil,
			jws.WithInsecureNoSignature(),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.Error(t, err)
		require.ErrorContains(t, err, `cannot be combined with jws.WithDetachedPayloadReader()`)
	})

	t.Run("Verify rejects none", func(t *testing.T) {
		t.Parallel()

		_, err := jws.Verify(
			[]byte(`eyJhbGciOiJub25lIn0..`),
			jws.WithKey(jwa.NoSignature(), nil),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.Error(t, err)
		require.ErrorContains(t, err, `cannot be used with jws.WithDetachedPayloadReader()`)
	})
}

func TestDetachedJSONOmissionForSignWithDetachedPayload(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-detached-payload`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.Sign(
		nil,
		jws.WithJSON(),
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayload(payload),
	)
	require.NoError(t, err)
	require.NotContains(t, string(signed), `"payload"`)

	var msg jws.Message
	require.NoError(t, stdjson.Unmarshal(signed, &msg))

	remarshaled, err := stdjson.Marshal(&msg)
	require.NoError(t, err)
	require.NotContains(t, string(remarshaled), `"payload"`)

	_, err = jws.Verify(remarshaled,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)
}

func TestStreamingDetachedEdDSARejected(t *testing.T) {
	t.Parallel()

	payload := []byte(`eddsa-rejected`)
	edKey, err := jwxtest.GenerateEd25519Key()
	require.NoError(t, err)

	_, err = jws.Sign(nil,
		jws.WithKey(jwa.EdDSA(), edKey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, `RFC 8032 EdDSA signs the full message`)

	signed, err := jws.Sign(nil, jws.WithKey(jwa.EdDSA(), edKey), jws.WithDetachedPayload(payload))
	require.NoError(t, err)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.EdDSA(), edKey.Public()),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, `RFC 8032 EdDSA signs the full message`)
}

func TestStreamingDetachedB64False(t *testing.T) {
	t.Parallel()

	payload := []byte(`raw-b64-false-payload`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set("b64", false))
	require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"b64"}))

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)
}

func TestStreamingDetachedLargePayload(t *testing.T) {
	t.Parallel()

	const size = 10 * 1024 * 1024
	largePayload := make([]byte, size)
	_, err := rand.Read(largePayload)
	require.NoError(t, err)

	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.RS256(), privkey),
		jws.WithDetachedPayloadReader(bytes.NewReader(largePayload)),
	)
	require.NoError(t, err)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.RS256(), &privkey.PublicKey),
		jws.WithDetachedPayloadReader(bytes.NewReader(largePayload)),
	)
	require.NoError(t, err)
}

func TestStreamingDetachedIOErrorMidStream(t *testing.T) {
	t.Parallel()

	payload := []byte(`mid-stream-io-error-payload`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	t.Run("Sign", func(t *testing.T) {
		t.Parallel()

		errReader := &failingReader{
			data:    payload,
			failAt:  10,
			failErr: fmt.Errorf("simulated I/O error"),
		}
		_, err := jws.Sign(nil,
			jws.WithKey(jwa.RS256(), privkey),
			jws.WithDetachedPayloadReader(errReader),
		)
		require.Error(t, err)
	})

	t.Run("Verify", func(t *testing.T) {
		t.Parallel()

		signed, err := jws.Sign(nil, jws.WithKey(jwa.RS256(), privkey), jws.WithDetachedPayload(payload))
		require.NoError(t, err)

		errReader := &failingReader{
			data:    payload,
			failAt:  10,
			failErr: fmt.Errorf("simulated I/O error"),
		}
		_, err = jws.Verify(signed,
			jws.WithKey(jwa.RS256(), &privkey.PublicKey),
			jws.WithDetachedPayloadReader(errReader),
		)
		require.Error(t, err)
	})
}

func TestStreamingDetachedVerifyContextCancel(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.RS256(), privkey),
		jws.WithDetachedPayload(payload),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel immediately

	// A reader that yields one byte per call; without context
	// plumbing the verifier would drain it to EOF regardless.
	r := &slowReader{data: payload}

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.RS256(), &privkey.PublicKey),
		jws.WithDetachedPayloadReader(r),
		jws.WithContext(ctx),
	)
	require.Error(t, err, `Verify should surface ctx.Err()`)
	require.ErrorIs(t, err, context.Canceled,
		`cancellation should propagate as context.Canceled`)
}

// slowReader returns one byte per Read until data is exhausted, then
// io.EOF. Forces the streaming verify loop to issue many small Reads.
type slowReader struct {
	data []byte
	i    int
}

func (s *slowReader) Read(p []byte) (int, error) {
	if s.i >= len(s.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = s.data[s.i]
	s.i++
	return 1, nil
}

func TestStreamingDetachedWrongKey(t *testing.T) {
	t.Parallel()

	payload := []byte(`wrong-key-payload`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)
	wrongKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.RS256(), privkey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.RS256(), &wrongKey.PublicKey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.Error(t, err)
	require.True(t, errors.Is(err, jws.VerifyError()), `error should be a VerifyError`)
	require.True(t, errors.Is(err, jws.VerificationError()), `error should be a VerificationError`)
}

func TestStreamingDetachedCrossVerify(t *testing.T) {
	t.Parallel()

	payload := []byte(`cross-verify-payload`)

	for _, tc := range streamingDetachedAlgCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// jws.Sign + WithDetachedPayload → streaming Verify
			signedTraditional, err := jws.Sign(nil, jws.WithKey(tc.alg, tc.signKey), jws.WithDetachedPayload(payload))
			require.NoError(t, err)

			_, err = jws.Verify(signedTraditional,
				jws.WithKey(tc.alg, tc.verifyKey),
				jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
			)
			require.NoError(t, err)

			// streaming Sign → jws.Verify + WithDetachedPayload
			signedStreaming, err := jws.Sign(nil,
				jws.WithKey(tc.alg, tc.signKey),
				jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
			)
			require.NoError(t, err)

			_, err = jws.Verify(signedStreaming, jws.WithKey(tc.alg, tc.verifyKey), jws.WithDetachedPayload(payload))
			require.NoError(t, err)
		})
	}
}

func TestStreamingDetachedRejectsMultipleKeysCompact(t *testing.T) {
	t.Parallel()

	payload := []byte(`multiple-keys-compact`)
	key1, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	key2, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	// Compact serialization can only carry a single signature; this is
	// enforced upstream in jws.Sign regardless of the streaming path.
	_, err = jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key1),
		jws.WithKey(jwa.HS256(), key2),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, `multiple signers`)
}

func TestStreamingDetachedMultiSigJSONRoundTrip(t *testing.T) {
	t.Parallel()

	payload := []byte(`multi-sig-json-round-trip payload with periods and spaces`)

	hmacKey, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	rsaKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	rsaPub, err := jwk.PublicKeyOf(rsaKey)
	require.NoError(t, err)
	ecdsaKey, err := jwxtest.GenerateEcdsaJwk(jwa.P256())
	require.NoError(t, err)
	ecdsaPub, err := jwk.PublicKeyOf(ecdsaKey)
	require.NoError(t, err)

	signed, err := jws.Sign(nil,
		jws.WithJSON(),
		jws.WithKey(jwa.HS256(), hmacKey),
		jws.WithKey(jwa.RS256(), rsaKey),
		jws.WithKey(jwa.ES256(), ecdsaKey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)

	// JSON output must contain a "signatures" array with three entries
	// and no "payload" member.
	var env struct {
		Signatures []struct {
			Protected string             `json:"protected"`
			Signature string             `json:"signature"`
			Header    stdjson.RawMessage `json:"header,omitempty"`
		} `json:"signatures"`
	}
	require.NoError(t, stdjson.Unmarshal(signed, &env))
	require.Len(t, env.Signatures, 3)
	require.NotContains(t, string(signed), `"payload"`)

	// Every signature must verify through the traditional detached-byte
	// path and through the streaming path.
	keys := []struct {
		alg jwa.SignatureAlgorithm
		key any
	}{
		{jwa.HS256(), hmacKey},
		{jwa.RS256(), rsaPub},
		{jwa.ES256(), ecdsaPub},
	}
	for _, k := range keys {
		_, err := jws.Verify(signed, jws.WithKey(k.alg, k.key), jws.WithDetachedPayload(payload))
		require.NoError(t, err, `jws.Verify with %s should succeed`, k.alg)

		_, err = jws.Verify(signed,
			jws.WithKey(k.alg, k.key),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.Error(t, err, `streaming verify currently supports only single-signature JSON`)
	}
}

func TestStreamingDetachedMultiSigPerSignerPublicHeaders(t *testing.T) {
	t.Parallel()

	payload := []byte(`multi-sig-per-signer-headers`)

	k1, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	k2, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	pub1 := jws.NewHeaders()
	require.NoError(t, pub1.Set("kid", "first"))
	pub2 := jws.NewHeaders()
	require.NoError(t, pub2.Set("kid", "second"))

	signed, err := jws.Sign(nil,
		jws.WithJSON(),
		jws.WithKey(jwa.HS256(), k1, jws.WithPublicHeaders(pub1)),
		jws.WithKey(jwa.HS256(), k2, jws.WithPublicHeaders(pub2)),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)

	var env struct {
		Signatures []struct {
			Header stdjson.RawMessage `json:"header"`
		} `json:"signatures"`
	}
	require.NoError(t, stdjson.Unmarshal(signed, &env))
	require.Len(t, env.Signatures, 2)
	require.Contains(t, string(env.Signatures[0].Header), `"kid":"first"`)
	require.Contains(t, string(env.Signatures[1].Header), `"kid":"second"`)

	_, err = jws.Verify(signed, jws.WithKey(jwa.HS256(), k1), jws.WithDetachedPayload(payload))
	require.NoError(t, err)
	_, err = jws.Verify(signed, jws.WithKey(jwa.HS256(), k2), jws.WithDetachedPayload(payload))
	require.NoError(t, err)
}

func TestStreamingDetachedMultiSigRejectsInconsistentB64(t *testing.T) {
	t.Parallel()

	payload := []byte(`multi-sig-b64-mismatch`)

	k1, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	k2, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	// First signer asks for b64=false via a protected header + crit.
	// Second signer does not, so its effective b64 is true. The JWS
	// would have a single payload segment that can't mean both things,
	// so signing must reject.
	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set("b64", false))
	require.NoError(t, hdr.Set(jws.CriticalKey, []string{"b64"}))

	_, err = jws.Sign(nil,
		jws.WithJSON(),
		jws.WithKey(jwa.HS256(), k1, jws.WithProtectedHeaders(hdr)),
		jws.WithKey(jwa.HS256(), k2),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, `"b64"`)
}

func TestStreamingDetachedRejectsNoKey(t *testing.T) {
	t.Parallel()

	payload := []byte(`no-key`)

	t.Run("Sign", func(t *testing.T) {
		t.Parallel()

		_, err := jws.Sign(nil,
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.Error(t, err)
		require.ErrorContains(t, err, `no signers available`)
	})

	t.Run("Verify", func(t *testing.T) {
		t.Parallel()

		_, err := jws.Verify([]byte(`eyJhbGciOiJIUzI1NiJ9..AAAA`),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.Error(t, err)
		require.ErrorContains(t, err, `no verifiers available`)
	})
}

func TestStreamingDetachedCompactIsIdentity(t *testing.T) {
	t.Parallel()

	payload := []byte(`with-compact-identity`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	plain, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)

	explicit, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithCompact(),
	)
	require.NoError(t, err)

	require.Equal(t, string(plain), string(explicit))
}

func TestStreamingDetachedJSONRoundTripMatrix(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-matrix-payload`)

	for _, tc := range streamingDetachedAlgCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			signed, err := jws.Sign(nil,
				jws.WithKey(tc.alg, tc.signKey),
				jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
				jws.WithJSON(),
			)
			require.NoError(t, err)
			require.True(t, bytes.HasPrefix(bytes.TrimSpace(signed), []byte{'{'}))

			_, err = jws.Verify(signed,
				jws.WithKey(tc.alg, tc.verifyKey),
				jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
			)
			require.NoError(t, err)

			_, err = jws.Verify(signed,
				jws.WithKey(tc.alg, tc.verifyKey),
				jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
				jws.WithJSON(),
			)
			require.NoError(t, err)
		})
	}
}

func TestStreamingDetachedJSONOmitsPayload(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-omits-payload`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithJSON(),
	)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, stdjson.Unmarshal(signed, &m))

	_, hasPayload := m["payload"]
	require.False(t, hasPayload, `JSON output must not contain a "payload" member per RFC 7515 Appendix F`)
	_, hasProtected := m["protected"]
	require.True(t, hasProtected)
	_, hasSignature := m["signature"]
	require.True(t, hasSignature)
	_, hasHeader := m["header"]
	require.False(t, hasHeader)
}

func TestStreamingDetachedJSONPretty(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-pretty-payload`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithJSON(jws.WithPretty(true)),
	)
	require.NoError(t, err)
	require.True(t, strings.Contains(string(signed), "\n"), `pretty JSON should contain newlines`)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)
}

func TestStreamingDetachedJSONWithUnprotectedHeader(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-unprotected-header`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	public := jws.NewHeaders()
	require.NoError(t, public.Set("kid", "unprotected-kid"))

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key, jws.WithPublicHeaders(public)),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithJSON(),
	)
	require.NoError(t, err)

	var m map[string]stdjson.RawMessage
	require.NoError(t, stdjson.Unmarshal(signed, &m))

	headerJSON, ok := m["header"]
	require.True(t, ok, `JSON output should contain "header" when unprotected headers are set`)
	require.Contains(t, string(headerJSON), `"kid":"unprotected-kid"`)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)
}

func TestStreamingDetachedJSONOutputVerifiableByVerify(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-output-verifiable`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.RS256(), privkey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithJSON(),
	)
	require.NoError(t, err)

	_, err = jws.Verify(signed, jws.WithKey(jwa.RS256(), &privkey.PublicKey), jws.WithDetachedPayload(payload))
	require.NoError(t, err)
}

func TestStreamingDetachedJSONRejectsMultiSignature(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-multi-sig`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	flat, err := jws.Sign(nil,
		jws.WithKey(jwa.RS256(), privkey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithJSON(),
	)
	require.NoError(t, err)

	var fm map[string]stdjson.RawMessage
	require.NoError(t, stdjson.Unmarshal(flat, &fm))

	one, err := stdjson.Marshal(map[string]stdjson.RawMessage{
		"protected": fm["protected"],
		"signature": fm["signature"],
	})
	require.NoError(t, err)
	multi := []byte(`{"signatures":[` + string(one) + `,` + string(one) + `]}`)

	_, err = jws.Verify(multi,
		jws.WithKey(jwa.RS256(), &privkey.PublicKey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), `single-signature`)
}

func TestStreamingDetachedJSONRejectsNonEmptyPayload(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-non-empty-payload`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	flat, err := jws.Sign(nil,
		jws.WithKey(jwa.RS256(), privkey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithJSON(),
	)
	require.NoError(t, err)

	var fm map[string]stdjson.RawMessage
	require.NoError(t, stdjson.Unmarshal(flat, &fm))
	fm["payload"] = stdjson.RawMessage(`"bm90LWVtcHR5"`)
	tampered, err := stdjson.Marshal(fm)
	require.NoError(t, err)

	_, err = jws.Verify(tampered,
		jws.WithKey(jwa.RS256(), &privkey.PublicKey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), `payload`)
}

func TestStreamingDetachedJSONRejectsPresentEmptyPayload(t *testing.T) {
	t.Parallel()

	// A JSON JWS carrying a present-but-empty "payload":"" member is an
	// in-band JWS over an empty payload, not a detached one. RFC 7515
	// Appendix F detached form omits the member entirely, so the streaming
	// detached path must reject a present member regardless of its value.
	payload := []byte(`json-empty-payload`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	flat, err := jws.Sign(nil,
		jws.WithKey(jwa.RS256(), privkey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithJSON(),
	)
	require.NoError(t, err)

	var fm map[string]stdjson.RawMessage
	require.NoError(t, stdjson.Unmarshal(flat, &fm))
	fm["payload"] = stdjson.RawMessage(`""`)
	withEmpty, err := stdjson.Marshal(fm)
	require.NoError(t, err)

	_, err = jws.Verify(withEmpty,
		jws.WithKey(jwa.RS256(), &privkey.PublicKey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), `payload`)
}

func TestStreamingDetachedJSONGeneralSingleSignature(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-general-single-sig`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	flat, err := jws.Sign(nil,
		jws.WithKey(jwa.RS256(), privkey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		jws.WithJSON(),
	)
	require.NoError(t, err)

	var fm map[string]stdjson.RawMessage
	require.NoError(t, stdjson.Unmarshal(flat, &fm))

	entry, err := stdjson.Marshal(map[string]stdjson.RawMessage{
		"protected": fm["protected"],
		"signature": fm["signature"],
	})
	require.NoError(t, err)
	general := []byte(`{"signatures":[` + string(entry) + `]}`)

	_, err = jws.Verify(general,
		jws.WithKey(jwa.RS256(), &privkey.PublicKey),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.NoError(t, err)
}

// TestStreamingDetachedHMACStringKeyError locks in that passing a string
// secret as an HMAC key on the streaming Verify path surfaces an actionable
// error pointing the caller at the required key shape. Historically the
// streaming HMAC branch returned the terse "HMAC key must be []byte, got
// string" once a caller managed to reach the hasher; in v4 that case is
// caught earlier by validateAlgorithmForKey with "unknown key type string",
// and the hasher now additionally routes unrecognized keys through
// keyconv.KeyAs[[]byte] to align with jws/jwsbb/sign.go's dispatchHMACSign.
// Either layer's message is acceptable as long as the user gets something
// more useful than a bare type mismatch.
func TestStreamingDetachedHMACStringKeyError(t *testing.T) {
	t.Parallel()

	payload := []byte(`hmac-string-key-payload`)
	key := jwxtest.GenerateSymmetricKey()

	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), "secret-as-string"),
		jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
	)
	require.Error(t, err)
	msg := err.Error()
	require.True(t,
		strings.Contains(msg, "keyconv") ||
			strings.Contains(msg, "convertible to []byte") ||
			strings.Contains(msg, "unknown key type"),
		"expected actionable key-type error, got %q", msg)
	// Must NOT surface the legacy terse message from newStreamingHasher.
	require.NotContains(t, msg, "HMAC key must be []byte, got")
}

// failingReader returns data up to failAt bytes, then fails with failErr.
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
