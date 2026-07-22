package jws_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

// signedWithKID signs payload with key, stamping the protected header's
// "kid" to kid so that jws.WithKeySet can route by key ID.
func signedWithKID(t *testing.T, payload []byte, key jwk.Key, kid string) []byte {
	t.Helper()
	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, kid))

	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)
	return signed
}

// TestVerifyWithUnsupportedKeyInSet checks that a JWK Set parsed with
// retention (WithStrictKeySetParsing(false)) is usable for verification:
// a signature routed to a supported key verifies, while one routed to an
// unsupported-key placeholder fails with a descriptive per-key error.
func TestVerifyWithUnsupportedKeyInSet(t *testing.T) {
	valid, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	require.NoError(t, valid.Set(jwk.KeyIDKey, "rsa1"))
	require.NoError(t, valid.Set(jwk.AlgorithmKey, jwa.RS256()))
	validJSON, err := json.Marshal(valid)
	require.NoError(t, err)

	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := []byte(`{"keys":[` + string(unknownEntry) + `,` + string(validJSON) + `]}`)

	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
	require.NoError(t, err)
	require.Equal(t, 2, set.Len())

	payload := []byte("hello world")

	t.Run("kid routes to the supported key and verifies", func(t *testing.T) {
		pub, err := valid.PublicKey()
		require.NoError(t, err)
		pubSet := jwk.NewSet()
		require.NoError(t, pubSet.AddKey(pub))

		signed := signedWithKID(t, payload, valid, "rsa1")
		got, err := jws.Verify(signed, jws.WithKeySet(pubSet))
		require.NoError(t, err)
		require.Equal(t, payload, got)
	})

	t.Run("kid routes to the placeholder and fails descriptively", func(t *testing.T) {
		// Any usable key can produce the signature; verification never
		// reaches it because the placeholder at kid "foo1" is rejected
		// first.
		signer, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err)
		signed := signedWithKID(t, payload, signer, "foo1")
		_, verr := jws.Verify(signed, jws.WithKeySet(set))
		require.Error(t, verr)
		require.Contains(t, verr.Error(), "foo1", "error should name the kid")
		require.Contains(t, verr.Error(), "FOO", "error should name the unsupported kty")
	})
}

// TestVerifyRequireKidFalseNamesPlaceholder pins that with
// WithRequireKid(false), a placeholder whose raw kty cannot match the
// header alg's key type is not silently dropped by the kty prefilter:
// the per-key rejection naming the kid and kty must surface instead of
// the generic "no matching keys" message.
func TestVerifyRequireKidFalseNamesPlaceholder(t *testing.T) {
	setJSON := []byte(`{"keys":[{"kty":"FOO","kid":"foo1","alg":"HS256","x":"dGVzdA"}]}`)
	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
	require.NoError(t, err)
	require.Equal(t, 1, set.Len())

	symKey, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	signed, err := jws.Sign([]byte("hello world"), jws.WithKey(jwa.HS256(), symKey))
	require.NoError(t, err)

	_, verr := jws.Verify(signed, jws.WithKeySet(set, jws.WithRequireKid(false)))
	require.Error(t, verr)
	require.Contains(t, verr.Error(), "foo1", "error should name the kid")
	require.Contains(t, verr.Error(), "FOO", "error should name the unsupported kty")
}

// parsePlaceholder parses a JWK Set containing a single unparseable
// entry with retention enabled and returns the resulting placeholder.
func parsePlaceholder(t *testing.T) jwk.Key {
	t.Helper()
	setJSON := []byte(`{"keys":[{"kty":"FOO","kid":"foo1","x":"dGVzdA"}]}`)
	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
	require.NoError(t, err)
	key, ok := set.LookupKeyID("foo1")
	require.True(t, ok)
	require.True(t, jwk.IsUnsupportedKey(key))
	return key
}

// recordingSigner is a custom Signer2 that records whether Sign was
// ever invoked.
type recordingSigner struct {
	alg    jwa.SignatureAlgorithm
	called *bool
}

func (s recordingSigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

func (s recordingSigner) Sign(_ any, _ []byte) ([]byte, error) {
	*s.called = true
	return []byte("bogus"), nil
}

// recordingVerifier is a custom Verifier2 that records whether Verify
// was ever invoked.
type recordingVerifier struct {
	called *bool
}

func (v recordingVerifier) Verify(_ any, _, _ []byte) error {
	*v.called = true
	return nil
}

// placeholderSinkProvider is a custom KeyProvider that sinks a fixed
// (alg, key) pair, bypassing the built-in key set provider entirely.
type placeholderSinkProvider struct {
	alg jwa.SignatureAlgorithm
	key jwk.Key
}

func (p placeholderSinkProvider) FetchKeys(_ context.Context, sink jws.KeySink, _ *jws.Signature, _ *jws.Message) error {
	sink.Key(p.alg, p.key)
	return nil
}

// TestSignWithKeyRejectsPlaceholderBeforeCustomSigner pins that
// jws.Sign with a placeholder passed directly via jws.WithKey fails up
// front — naming the kid and kty — and that a custom registered signer
// for the algorithm is never handed the placeholder.
func TestSignWithKeyRejectsPlaceholderBeforeCustomSigner(t *testing.T) {
	placeholder := parsePlaceholder(t)

	alg := jwa.NewSignatureAlgorithm("TEST-PLACEHOLDER-SIGN")
	called := false
	require.NoError(t, jws.RegisterSigner(alg, recordingSigner{alg: alg, called: &called}))
	defer func() {
		jws.UnregisterSigner(alg)
		jwa.UnregisterSignatureAlgorithm(alg)
	}()

	_, err := jws.Sign([]byte("hello world"), jws.WithKey(alg, placeholder))
	require.Error(t, err)
	require.False(t, called, "custom signer must not be invoked with a placeholder")
	require.Contains(t, err.Error(), "foo1", "error should name the kid")
	require.Contains(t, err.Error(), "FOO", "error should name the unsupported kty")
}

// TestVerifyWithKeyRejectsPlaceholderBeforeCustomVerifier pins that
// jws.Verify with a placeholder passed directly via jws.WithKey fails
// up front and that a custom registered verifier for the algorithm is
// never handed the placeholder.
func TestVerifyWithKeyRejectsPlaceholderBeforeCustomVerifier(t *testing.T) {
	placeholder := parsePlaceholder(t)

	alg := jwa.NewSignatureAlgorithm("TEST-PLACEHOLDER-VERIFY")
	called := false
	require.NoError(t, jws.RegisterVerifier(alg, recordingVerifier{called: &called}))
	defer func() {
		jws.UnregisterVerifier(alg)
		jwa.UnregisterSignatureAlgorithm(alg)
	}()

	symKey, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	signed, err := jws.Sign([]byte("hello world"), jws.WithKey(jwa.HS256(), symKey))
	require.NoError(t, err)

	_, verr := jws.Verify(signed, jws.WithKey(alg, placeholder))
	require.Error(t, verr)
	require.False(t, called, "custom verifier must not be invoked with a placeholder")
	require.Contains(t, verr.Error(), "foo1", "error should name the kid")
	require.Contains(t, verr.Error(), "FOO", "error should name the unsupported kty")
}

// TestVerifyCustomKeyProviderRejectsPlaceholder pins that a placeholder
// sunk by a custom KeyProvider — a path that bypasses the built-in key
// set provider and its checks — is rejected before the verifier runs,
// and that a custom registered verifier is never handed the placeholder.
func TestVerifyCustomKeyProviderRejectsPlaceholder(t *testing.T) {
	placeholder := parsePlaceholder(t)

	alg := jwa.NewSignatureAlgorithm("TEST-PLACEHOLDER-PROVIDER")
	called := false
	require.NoError(t, jws.RegisterVerifier(alg, recordingVerifier{called: &called}))
	defer func() {
		jws.UnregisterVerifier(alg)
		jwa.UnregisterSignatureAlgorithm(alg)
	}()

	symKey, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	signed, err := jws.Sign([]byte("hello world"), jws.WithKey(jwa.HS256(), symKey))
	require.NoError(t, err)

	_, verr := jws.Verify(signed, jws.WithKeyProvider(placeholderSinkProvider{alg: alg, key: placeholder}))
	require.Error(t, verr)
	require.False(t, called, "custom verifier must not be invoked with a placeholder")
	require.Contains(t, verr.Error(), "foo1", "error should name the kid")
	require.Contains(t, verr.Error(), "FOO", "error should name the unsupported kty")
}

// fixedSetFetcher is a jwk.Fetcher that returns the same JWK Set for
// any URL, standing in for a remote "jku" JWKS endpoint.
type fixedSetFetcher struct {
	set jwk.Set
}

func (f fixedSetFetcher) Fetch(_ context.Context, _ string, _ ...jwk.FetchOption) (jwk.Set, error) {
	return f.set, nil
}

// TestVerifyAutoNamesPlaceholderFromJKU pins that the "jku" key
// provider rejects a placeholder matched by kid with an error naming
// the kid, the kty, the JWKS URL, and the retained parse reason,
// instead of a generic key-classification failure.
func TestVerifyAutoNamesPlaceholderFromJKU(t *testing.T) {
	setJSON := []byte(`{"keys":[{"kty":"FOO","kid":"foo1","x":"dGVzdA"}]}`)
	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
	require.NoError(t, err)

	symKey, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, "foo1"))
	require.NoError(t, hdr.Set(jws.JWKSetURLKey, "https://example.test/jwks"))
	signed, err := jws.Sign([]byte("hello world"), jws.WithKey(jwa.HS256(), symKey, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)

	_, verr := jws.Verify(signed, jws.WithVerifyAuto(fixedSetFetcher{set: set}))
	require.Error(t, verr)
	require.Contains(t, verr.Error(), "foo1", "error should name the kid")
	require.Contains(t, verr.Error(), "FOO", "error should name the unsupported kty")
	require.Contains(t, verr.Error(), "https://example.test/jwks", "error should name the jku URL")
}
