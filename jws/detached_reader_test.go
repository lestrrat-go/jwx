package jws_test

import (
	"bytes"
	"crypto/rand"
	stdbase64 "encoding/base64"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

type detachedAlgCase struct {
	name      string
	alg       jwa.SignatureAlgorithm
	signKey   any
	verifyKey any
}

func detachedAlgCases(t *testing.T) []detachedAlgCase {
	t.Helper()

	symmetricKey, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	rsaKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	rsaPub, err := jwk.PublicKeyOf(rsaKey)
	require.NoError(t, err)

	ecdsaKey, err := jwxtest.GenerateEcdsaJwk()
	require.NoError(t, err)
	ecdsaPub, err := jwk.PublicKeyOf(ecdsaKey)
	require.NoError(t, err)

	return []detachedAlgCase{
		{name: "HS256", alg: jwa.HS256(), signKey: symmetricKey, verifyKey: symmetricKey},
		{name: "RS256", alg: jwa.RS256(), signKey: rsaKey, verifyKey: rsaPub},
		{name: "PS256", alg: jwa.PS256(), signKey: rsaKey, verifyKey: rsaPub},
		{name: "ES256", alg: jwa.ES256(), signKey: ecdsaKey, verifyKey: ecdsaPub},
	}
}

func TestSignDetachedReaderCompactRoundTrip(t *testing.T) {
	t.Parallel()

	payload := []byte(`payload.with.periods and spaces`)

	for _, tc := range detachedAlgCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			signed, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(tc.alg, tc.signKey))
			require.NoError(t, err)
			require.Contains(t, string(signed), "..")

			err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(tc.alg, tc.verifyKey))
			require.NoError(t, err)
		})
	}
}

func TestSignDetachedReaderJSONRoundTrip(t *testing.T) {
	t.Parallel()

	payload := []byte(`reader-json-payload`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.SignDetachedReader(
		bytes.NewReader(payload),
		jws.WithJSON(),
		jws.WithKey(jwa.HS256(), key),
	)
	require.NoError(t, err)
	require.NotContains(t, string(signed), `"payload"`)

	err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
}

func TestVerifyDetachedReaderFormatMismatch(t *testing.T) {
	t.Parallel()

	payload := []byte(`reader-json-mismatch`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.SignDetachedReader(
		bytes.NewReader(payload),
		jws.WithJSON(),
		jws.WithKey(jwa.HS256(), key),
	)
	require.NoError(t, err)

	err = jws.VerifyDetachedReader(
		signed,
		bytes.NewReader(payload),
		jws.WithCompact(),
		jws.WithKey(jwa.HS256(), key),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, `input format mismatch`)
	require.ErrorContains(t, err, `jws.WithCompact()`)
	require.ErrorContains(t, err, `jws.WithJSON()`)
}

func TestVerifyDetachedReaderKeyUsed(t *testing.T) {
	t.Parallel()

	payload := []byte(`key-used`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)

	var used any
	err = jws.VerifyDetachedReader(
		signed,
		bytes.NewReader(payload),
		jws.WithKey(jwa.HS256(), key),
		jws.WithKeyUsed(&used),
	)
	require.NoError(t, err)
	require.Same(t, key, used)
}

func TestVerifyDetachedReaderCritAutoAllowsB64(t *testing.T) {
	t.Parallel()

	payload := []byte(`raw.payload.with.periods`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	protected := jws.NewHeaders()
	require.NoError(t, protected.Set("b64", false))
	require.NoError(t, protected.Set(jws.CriticalKey, []string{"b64"}))

	signed, err := jws.SignDetachedReader(
		bytes.NewReader(payload),
		jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(protected)),
	)
	require.NoError(t, err)

	err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
}

func TestDetachedReaderWithBase64Encoder(t *testing.T) {
	t.Parallel()

	payload := []byte(`padded-reader-encoding`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	_, err = jws.SignDetachedReader(
		bytes.NewReader(payload),
		jws.WithKey(jwa.HS256(), key),
		jws.WithBase64Encoder(stdbase64.URLEncoding),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, `jws.WithBase64Encoder() is not supported by SignDetachedReader`)

	signed, err := jws.SignDetachedReader(
		bytes.NewReader(payload),
		jws.WithKey(jwa.HS256(), key),
	)
	require.NoError(t, err)

	err = jws.VerifyDetachedReader(
		signed,
		bytes.NewReader(payload),
		jws.WithKey(jwa.HS256(), key),
		jws.WithBase64Encoder(stdbase64.URLEncoding),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, `jws.WithBase64Encoder() is not supported by VerifyDetachedReader`)
}

func TestDetachedReaderUnsupportedUsageGuidance(t *testing.T) {
	t.Parallel()

	payload := []byte(`unsupported-guidance`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	t.Run("SignDetachedReader rejects detached payload option", func(t *testing.T) {
		t.Parallel()

		_, err := jws.SignDetachedReader(
			bytes.NewReader(payload),
			jws.WithKey(jwa.HS256(), key),
			jws.WithDetachedPayload(payload),
		)
		require.Error(t, err)
		require.ErrorContains(t, err, `use jws.Sign with jws.WithDetachedPayload()`)
	})

	t.Run("VerifyDetachedReader rejects none", func(t *testing.T) {
		t.Parallel()

		err := jws.VerifyDetachedReader(
			[]byte(`eyJhbGciOiJub25lIn0..`),
			bytes.NewReader(payload),
			jws.WithKey(jwa.NoSignature(), nil),
		)
		require.Error(t, err)
		require.ErrorContains(t, err, `cannot be used with VerifyDetachedReader`)
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

	err = jws.VerifyDetachedReader(remarshaled, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
}

func TestDetachedReaderEdDSARejected(t *testing.T) {
	t.Parallel()

	payload := []byte(`eddsa-rejected`)
	edKey, err := jwxtest.GenerateEd25519Key()
	require.NoError(t, err)

	_, err = jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.EdDSA(), edKey))
	require.Error(t, err)
	require.ErrorContains(t, err, `does not support SignDetachedReader`)

	signed, err := jws.Sign(nil, jws.WithKey(jwa.EdDSA(), edKey), jws.WithDetachedPayload(payload))
	require.NoError(t, err)

	err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(jwa.EdDSA(), edKey.Public()))
	require.Error(t, err)
	require.ErrorContains(t, err, `does not support VerifyDetachedReader`)
}

func TestSignDetachedReaderB64False(t *testing.T) {
	t.Parallel()

	payload := []byte(`raw-b64-false-payload`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set("b64", false))
	require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"b64"}))

	signed, err := jws.SignDetachedReader(
		bytes.NewReader(payload),
		jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)),
	)
	require.NoError(t, err)

	err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
}

func TestDetachedReaderLargePayload(t *testing.T) {
	t.Parallel()

	const size = 10 * 1024 * 1024
	largePayload := make([]byte, size)
	_, err := rand.Read(largePayload)
	require.NoError(t, err)

	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	signed, err := jws.SignDetachedReader(bytes.NewReader(largePayload), jws.WithKey(jwa.RS256(), privkey))
	require.NoError(t, err)

	err = jws.VerifyDetachedReader(signed, bytes.NewReader(largePayload), jws.WithKey(jwa.RS256(), &privkey.PublicKey))
	require.NoError(t, err)
}

func TestDetachedReaderIOErrorMidStream(t *testing.T) {
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
		_, err := jws.SignDetachedReader(errReader, jws.WithKey(jwa.RS256(), privkey))
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
		err = jws.VerifyDetachedReader(signed, errReader, jws.WithKey(jwa.RS256(), &privkey.PublicKey))
		require.Error(t, err)
	})
}

func TestVerifyDetachedReaderWrongKey(t *testing.T) {
	t.Parallel()

	payload := []byte(`wrong-key-payload`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)
	wrongKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	signed, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.RS256(), privkey))
	require.NoError(t, err)

	err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(jwa.RS256(), &wrongKey.PublicKey))
	require.Error(t, err)
	require.True(t, errors.Is(err, jws.VerifyError()), `error should be a VerifyError`)
	require.True(t, errors.Is(err, jws.VerificationError()), `error should be a VerificationError`)
}

func TestDetachedReaderCrossVerify(t *testing.T) {
	t.Parallel()

	payload := []byte(`cross-verify-payload`)

	for _, tc := range detachedAlgCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// jws.Sign + WithDetachedPayload → VerifyDetachedReader
			signedTraditional, err := jws.Sign(nil, jws.WithKey(tc.alg, tc.signKey), jws.WithDetachedPayload(payload))
			require.NoError(t, err)

			err = jws.VerifyDetachedReader(signedTraditional, bytes.NewReader(payload), jws.WithKey(tc.alg, tc.verifyKey))
			require.NoError(t, err)

			// SignDetachedReader → jws.Verify + WithDetachedPayload
			signedStreaming, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(tc.alg, tc.signKey))
			require.NoError(t, err)

			_, err = jws.Verify(signedStreaming, jws.WithKey(tc.alg, tc.verifyKey), jws.WithDetachedPayload(payload))
			require.NoError(t, err)
		})
	}
}

func TestSignDetachedReaderRejectsMultipleKeys(t *testing.T) {
	t.Parallel()

	payload := []byte(`multiple-keys`)
	key1, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	key2, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	_, err = jws.SignDetachedReader(bytes.NewReader(payload),
		jws.WithKey(jwa.HS256(), key1),
		jws.WithKey(jwa.HS256(), key2),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, `exactly one jws.WithKey()`)
}

func TestDetachedReaderRejectsNoKey(t *testing.T) {
	t.Parallel()

	payload := []byte(`no-key`)

	t.Run("Sign", func(t *testing.T) {
		t.Parallel()

		_, err := jws.SignDetachedReader(bytes.NewReader(payload))
		require.Error(t, err)
		require.ErrorContains(t, err, `jws.WithKey() must be specified`)
	})

	t.Run("Verify", func(t *testing.T) {
		t.Parallel()

		err := jws.VerifyDetachedReader([]byte(`eyJhbGciOiJIUzI1NiJ9..AAAA`), bytes.NewReader(payload))
		require.Error(t, err)
		require.ErrorContains(t, err, `jws.WithKey() must be specified`)
	})
}

func TestSignDetachedReaderWithCompactIsIdentity(t *testing.T) {
	t.Parallel()

	payload := []byte(`with-compact-identity`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	plain, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)

	explicit, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key), jws.WithCompact())
	require.NoError(t, err)

	require.Equal(t, string(plain), string(explicit))
}

func TestSignDetachedReaderJSONRoundTripMatrix(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-matrix-payload`)

	for _, tc := range detachedAlgCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			signed, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(tc.alg, tc.signKey), jws.WithJSON())
			require.NoError(t, err)
			require.True(t, bytes.HasPrefix(bytes.TrimSpace(signed), []byte{'{'}))

			err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(tc.alg, tc.verifyKey))
			require.NoError(t, err)

			err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(tc.alg, tc.verifyKey), jws.WithJSON())
			require.NoError(t, err)
		})
	}
}

func TestSignDetachedReaderJSONOmitsPayload(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-omits-payload`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key), jws.WithJSON())
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

func TestSignDetachedReaderJSONPretty(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-pretty-payload`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	signed, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key), jws.WithJSON(jws.WithPretty(true)))
	require.NoError(t, err)
	require.True(t, strings.Contains(string(signed), "\n"), `pretty JSON should contain newlines`)

	err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
}

func TestSignDetachedReaderJSONWithUnprotectedHeader(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-unprotected-header`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	public := jws.NewHeaders()
	require.NoError(t, public.Set("kid", "unprotected-kid"))

	signed, err := jws.SignDetachedReader(
		bytes.NewReader(payload),
		jws.WithKey(jwa.HS256(), key, jws.WithPublicHeaders(public)),
		jws.WithJSON(),
	)
	require.NoError(t, err)

	var m map[string]stdjson.RawMessage
	require.NoError(t, stdjson.Unmarshal(signed, &m))

	headerJSON, ok := m["header"]
	require.True(t, ok, `JSON output should contain "header" when unprotected headers are set`)
	require.Contains(t, string(headerJSON), `"kid":"unprotected-kid"`)

	err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
}

func TestSignDetachedReaderJSONOutputVerifiableByVerify(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-output-verifiable`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	signed, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.RS256(), privkey), jws.WithJSON())
	require.NoError(t, err)

	_, err = jws.Verify(signed, jws.WithKey(jwa.RS256(), &privkey.PublicKey), jws.WithDetachedPayload(payload))
	require.NoError(t, err)
}

func TestVerifyDetachedReaderJSONRejectsMultiSignature(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-multi-sig`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	flat, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.RS256(), privkey), jws.WithJSON())
	require.NoError(t, err)

	var fm map[string]stdjson.RawMessage
	require.NoError(t, stdjson.Unmarshal(flat, &fm))

	one, err := stdjson.Marshal(map[string]stdjson.RawMessage{
		"protected": fm["protected"],
		"signature": fm["signature"],
	})
	require.NoError(t, err)
	multi := []byte(`{"signatures":[` + string(one) + `,` + string(one) + `]}`)

	err = jws.VerifyDetachedReader(multi, bytes.NewReader(payload), jws.WithKey(jwa.RS256(), &privkey.PublicKey))
	require.Error(t, err)
	require.Contains(t, err.Error(), `single-signature`)
}

func TestVerifyDetachedReaderJSONRejectsNonEmptyPayload(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-non-empty-payload`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	flat, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.RS256(), privkey), jws.WithJSON())
	require.NoError(t, err)

	var fm map[string]stdjson.RawMessage
	require.NoError(t, stdjson.Unmarshal(flat, &fm))
	fm["payload"] = stdjson.RawMessage(`"bm90LWVtcHR5"`)
	tampered, err := stdjson.Marshal(fm)
	require.NoError(t, err)

	err = jws.VerifyDetachedReader(tampered, bytes.NewReader(payload), jws.WithKey(jwa.RS256(), &privkey.PublicKey))
	require.Error(t, err)
	require.Contains(t, err.Error(), `payload`)
}

func TestVerifyDetachedReaderJSONAcceptsEmptyPayload(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-empty-payload`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	flat, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.RS256(), privkey), jws.WithJSON())
	require.NoError(t, err)

	var fm map[string]stdjson.RawMessage
	require.NoError(t, stdjson.Unmarshal(flat, &fm))
	fm["payload"] = stdjson.RawMessage(`""`)
	withEmpty, err := stdjson.Marshal(fm)
	require.NoError(t, err)

	err = jws.VerifyDetachedReader(withEmpty, bytes.NewReader(payload), jws.WithKey(jwa.RS256(), &privkey.PublicKey))
	require.NoError(t, err)
}

func TestVerifyDetachedReaderJSONGeneralSingleSignature(t *testing.T) {
	t.Parallel()

	payload := []byte(`json-general-single-sig`)
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	flat, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.RS256(), privkey), jws.WithJSON())
	require.NoError(t, err)

	var fm map[string]stdjson.RawMessage
	require.NoError(t, stdjson.Unmarshal(flat, &fm))

	entry, err := stdjson.Marshal(map[string]stdjson.RawMessage{
		"protected": fm["protected"],
		"signature": fm["signature"],
	})
	require.NoError(t, err)
	general := []byte(`{"signatures":[` + string(entry) + `]}`)

	err = jws.VerifyDetachedReader(general, bytes.NewReader(payload), jws.WithKey(jwa.RS256(), &privkey.PublicKey))
	require.NoError(t, err)
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
