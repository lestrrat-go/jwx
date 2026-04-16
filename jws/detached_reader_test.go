package jws_test

import (
	"bytes"
	stdbase64 "encoding/base64"
	stdjson "encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

func TestSignDetachedReaderCompactRoundTrip(t *testing.T) {
	t.Parallel()

	payload := []byte(`payload.with.periods and spaces`)

	type testCase struct {
		name      string
		alg       jwa.SignatureAlgorithm
		signKey   any
		verifyKey any
	}

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

	cases := []testCase{
		{
			name:      "HMAC",
			alg:       jwa.HS256(),
			signKey:   symmetricKey,
			verifyKey: symmetricKey,
		},
		{
			name:      "RSA",
			alg:       jwa.RS256(),
			signKey:   rsaKey,
			verifyKey: rsaPub,
		},
		{
			name:      "ECDSA",
			alg:       jwa.ES256(),
			signKey:   ecdsaKey,
			verifyKey: ecdsaPub,
		},
	}

	for _, tc := range cases {
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

	signed, err := jws.SignDetachedReader(
		bytes.NewReader(payload),
		jws.WithKey(jwa.HS256(), key),
		jws.WithBase64Encoder(stdbase64.URLEncoding),
	)
	require.NoError(t, err)
	require.Contains(t, string(signed), "=")

	err = jws.VerifyDetachedReader(
		signed,
		bytes.NewReader(payload),
		jws.WithKey(jwa.HS256(), key),
		jws.WithBase64Encoder(stdbase64.URLEncoding),
	)
	require.NoError(t, err)
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
