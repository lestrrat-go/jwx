package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

func TestCriticalHeaderValidation(t *testing.T) {
	payload := []byte(`hello world`)

	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	// Helper to sign with given protected headers
	sign := func(t *testing.T, hdrs jws.Headers) []byte {
		t.Helper()
		signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)))
		require.NoError(t, err, `jws.Sign should succeed`)
		return signed
	}

	t.Run("No crit header", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		signed := sign(t, hdrs)
		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jws.Verify should succeed without crit header`)
	})

	t.Run("crit with b64 present in header", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("b64", false))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"b64"}))

		signed, err := jws.Sign(nil, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)), jws.WithDetachedPayload(payload))
		require.NoError(t, err, `jws.Sign should succeed`)

		_, err = jws.Verify(signed, jws.WithKey(jwa.HS256(), key), jws.WithDetachedPayload(payload))
		require.NoError(t, err, `jws.Verify should succeed when crit-listed header is present`)
	})

	t.Run("crit with custom header present succeeds", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-custom", "custom-value"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-custom"}))
		signed := sign(t, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jws.Verify should succeed when crit-listed header is present`)
	})

	t.Run("crit references header not present fails", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-missing"}))
		signed := sign(t, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify should fail when crit references absent header`)
		require.ErrorContains(t, err, `not present in the protected header`)
	})

	t.Run("crit with standard header name fails", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"alg"}))
		signed := sign(t, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify should fail when crit contains standard header name`)
		require.ErrorContains(t, err, `standard header parameter`)
	})

	t.Run("crit with empty array fails", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{}))
		signed := sign(t, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify should fail when crit is empty`)
		require.ErrorContains(t, err, `must not be empty`)
	})

	t.Run("crit with multiple headers all present succeeds", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-one", "v1"))
		require.NoError(t, hdrs.Set("x-two", "v2"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-one", "x-two"}))
		signed := sign(t, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jws.Verify should succeed when all crit-listed headers are present`)
	})

	t.Run("crit with multiple headers one missing fails", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-present", "value"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-present", "x-absent"}))
		signed := sign(t, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify should fail when any crit-listed header is missing`)
		require.ErrorContains(t, err, `x-absent`)
	})
}

func TestCriticalHeaderValidationFastPath(t *testing.T) {
	payload := []byte(`hello world`)

	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	sign := func(t *testing.T, hdrs jws.Headers) []byte {
		t.Helper()
		signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)))
		require.NoError(t, err, `jws.Sign should succeed`)
		return signed
	}

	t.Run("No crit header", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		signed := sign(t, hdrs)
		_, err := jws.VerifyCompactFast(key, signed, jwa.HS256())
		require.NoError(t, err, `VerifyCompactFast should succeed without crit header`)
	})

	t.Run("crit with custom header present succeeds", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-custom", "custom-value"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-custom"}))
		signed := sign(t, hdrs)

		_, err := jws.VerifyCompactFast(key, signed, jwa.HS256())
		require.NoError(t, err, `VerifyCompactFast should succeed when crit-listed header is present`)
	})

	t.Run("crit references header not present fails", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-missing"}))
		signed := sign(t, hdrs)

		_, err := jws.VerifyCompactFast(key, signed, jwa.HS256())
		require.Error(t, err, `VerifyCompactFast should fail when crit references absent header`)
		require.ErrorContains(t, err, `not present in the protected header`)
	})

	t.Run("crit with standard header name fails", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"alg"}))
		signed := sign(t, hdrs)

		_, err := jws.VerifyCompactFast(key, signed, jwa.HS256())
		require.Error(t, err, `VerifyCompactFast should fail when crit contains standard header name`)
		require.ErrorContains(t, err, `standard header parameter`)
	})

	t.Run("crit with empty array fails", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{}))
		signed := sign(t, hdrs)

		_, err := jws.VerifyCompactFast(key, signed, jwa.HS256())
		require.Error(t, err, `VerifyCompactFast should fail when crit is empty`)
		require.ErrorContains(t, err, `must not be empty`)
	})

	t.Run("crit with multiple headers all present succeeds", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-one", "v1"))
		require.NoError(t, hdrs.Set("x-two", "v2"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-one", "x-two"}))
		signed := sign(t, hdrs)

		_, err := jws.VerifyCompactFast(key, signed, jwa.HS256())
		require.NoError(t, err, `VerifyCompactFast should succeed when all crit-listed headers are present`)
	})

	t.Run("crit with multiple headers one missing fails", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-present", "value"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-present", "x-absent"}))
		signed := sign(t, hdrs)

		_, err := jws.VerifyCompactFast(key, signed, jwa.HS256())
		require.Error(t, err, `VerifyCompactFast should fail when any crit-listed header is missing`)
		require.ErrorContains(t, err, `x-absent`)
	})
}
