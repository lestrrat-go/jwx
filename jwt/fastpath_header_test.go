package jwt_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
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
// jwt.Parse takes the VerifyCompactFast fast path, which (via fastjson)
// accepted a protected header carrying a duplicate "alg" — a header that
// jws.Verify (encoding/json/v2) rejects. The fast path now defers any
// non-minimal header to jws.Verify, so jws.Verify, jws.VerifyCompactFast and
// jwt.Parse agree: the duplicate is rejected, the well-formed control is
// accepted.
func TestParseDuplicateHeaderParameters(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	payload := `{"sub":"alice"}`

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
}
