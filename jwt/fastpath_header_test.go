package jwt_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

func signHS256Compact(key []byte, hdrJSON, payload string) []byte {
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(hdrJSON)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return []byte(signingInput + "." + sig)
}

// TestParseDuplicateHeaderParameters is the regression test for issue #2234.
// jwt.Parse takes the VerifyCompactFast fast path, which originally
// accepted a protected header carrying a duplicate "alg" — a header that
// jws.Verify (encoding/json/v2) rejects. The fast path now defers any
// non-minimal header to jws.Verify, so jws.Verify, jws.VerifyCompactFast and
// jwt.Parse agree: the duplicate is rejected, the well-formed control is
// accepted.
func TestParseDuplicateHeaderParameters(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	payload := `{"sub":"alice"}`

	t.Run("invalid string encoding rejected by every entry point", func(t *testing.T) {
		for _, header := range []string{
			"{\"alg\":\"HS256\",\"typ\":\"a\x01b\"}",
			"{\"alg\":\"HS256\",\"kid\":\"\xff\"}",
		} {
			signed := signHS256Compact(key, header, payload)
			_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
			require.Error(t, err)
			_, err = jws.VerifyCompactFast(key, signed, jwa.HS256())
			require.Error(t, err)
			_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key), jwt.WithValidate(false))
			require.Error(t, err)
		}
	})

	dup := signHS256Compact(key, `{"alg":"HS256","alg":"none"}`, payload)
	control := signHS256Compact(key, `{"alg":"HS256","typ":"JWT"}`, payload)

	t.Run("duplicate alg rejected by every entry point", func(t *testing.T) {
		_, err := jws.Verify(dup, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify must reject duplicate alg`)

		_, err = jws.VerifyCompactFast(key, dup, jwa.HS256())
		require.Error(t, err, `jws.VerifyCompactFast must reject duplicate alg`)

		_, err = jwt.Parse(dup, jwt.WithKey(jwa.HS256(), key), jwt.WithValidate(false))
		require.Error(t, err, `jwt.Parse must reject duplicate alg`)
	})

	t.Run("well-formed control accepted by every entry point", func(t *testing.T) {
		_, err := jws.Verify(control, jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err)

		_, err = jws.VerifyCompactFast(key, control, jwa.HS256())
		require.NoError(t, err)

		tok, err := jwt.Parse(control, jwt.WithKey(jwa.HS256(), key), jwt.WithValidate(false))
		require.NoError(t, err)
		sub, ok := tok.Subject()
		require.True(t, ok)
		require.Equal(t, "alice", sub)
	})

	t.Run("non-string typ rejected by every entry point", func(t *testing.T) {
		// A genuinely-signed header with a non-string "typ" is rejected by
		// jws.Verify (json/v2 typed decode); the fast path must agree rather
		// than accept it, or jwt.Parse would be laxer than jws.Verify.
		badTyp := signHS256Compact(key, `{"alg":"HS256","typ":123}`, payload)

		_, err := jws.Verify(badTyp, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify must reject a non-string typ`)

		_, err = jws.VerifyCompactFast(key, badTyp, jwa.HS256())
		require.Error(t, err, `jws.VerifyCompactFast must reject a non-string typ`)

		_, err = jwt.Parse(badTyp, jwt.WithKey(jwa.HS256(), key), jwt.WithValidate(false))
		require.Error(t, err, `jwt.Parse must reject a non-string typ`)
	})
}

// TestParseMissingAlgAgreesAcrossOptions checks that a compact JWS whose
// protected header has no "alg" gets the same answer from jwt.Parse no matter
// which options select the verification path. The algorithm always comes from
// the caller (WithKey) or the key ("alg" in the JWK), so a missing header
// "alg" is accepted when the signature verifies under that algorithm, and
// rejected when it does not.
func TestParseMissingAlgAgreesAcrossOptions(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	otherKey := []byte("fedcba9876543210fedcba9876543210")
	payload := `{"sub":"alice"}`

	jwkKey, err := jwk.Import[jwk.Key](key)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, "k1"))
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, jwa.HS256()))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(jwkKey))

	parsers := []struct {
		name    string
		options []jwt.ParseOption
	}{
		// jwt.Parse's dedicated fast path (WithKey, optionally WithValidate).
		{name: "WithKey", options: []jwt.ParseOption{jwt.WithKey(jwa.HS256(), key)}},
		{name: "WithKey and WithValidate(false)", options: []jwt.ParseOption{jwt.WithKey(jwa.HS256(), key), jwt.WithValidate(false)}},
		// Any other option skips that fast path, but verification still tries
		// VerifyCompactFast first for a single WithKey.
		{name: "WithKey and WithContext", options: []jwt.ParseOption{jwt.WithKey(jwa.HS256(), key), jwt.WithContext(t.Context())}},
		// Lenient base64 never uses VerifyCompactFast.
		{name: "WithKey and lenient base64", options: []jwt.ParseOption{jwt.WithKey(jwa.HS256(), key), jwt.WithStrictBase64Encoding(false)}},
		{name: "WithKeySet", options: []jwt.ParseOption{jwt.WithKeySet(set)}},
	}

	t.Run("signed with the expected key is accepted", func(t *testing.T) {
		signed := signHS256Compact(key, `{"kid":"k1"}`, payload)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jws.Verify uses the caller's algorithm when "alg" is missing`)

		for _, p := range parsers {
			tok, err := jwt.Parse(signed, p.options...)
			require.NoError(t, err, `jwt.Parse with %s`, p.name)
			sub, ok := tok.Subject()
			require.True(t, ok, `jwt.Parse with %s`, p.name)
			require.Equal(t, "alice", sub, `jwt.Parse with %s`, p.name)
		}
	})

	t.Run("signed with another key is rejected", func(t *testing.T) {
		signed := signHS256Compact(otherKey, `{"kid":"k1"}`, payload)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err)

		for _, p := range parsers {
			_, err := jwt.Parse(signed, p.options...)
			require.Error(t, err, `jwt.Parse with %s`, p.name)
		}
	})

	t.Run("an alg that disagrees with the caller's is rejected", func(t *testing.T) {
		signed := signHS256Compact(key, `{"alg":"HS384","kid":"k1"}`, payload)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err)

		for _, p := range parsers {
			_, err := jwt.Parse(signed, p.options...)
			require.Error(t, err, `jwt.Parse with %s`, p.name)
		}
	})
}
