package jwk_test

import (
	"crypto"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// validRSAJWK generates a fresh RSA key, assigns it the given kid, and
// returns its JSON serialization. It is the "good" key that must remain
// usable even when the surrounding set contains an unparseable entry.
func validRSAJWK(t *testing.T, kid string) []byte {
	t.Helper()
	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	buf, err := json.Marshal(key)
	require.NoError(t, err)
	return buf
}

func makeSetJSON(entries ...[]byte) []byte {
	buf := []byte(`{"keys":[`)
	for i, e := range entries {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, e...)
	}
	buf = append(buf, ']', '}')
	return buf
}

func TestIsUnsupportedKey(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	set, err := jwk.Parse(setJSON)
	require.NoError(t, err)

	k0, ok := set.Key(0)
	require.True(t, ok)
	require.True(t, jwk.IsUnsupportedKey(k0), "placeholder must be detected")

	k1, ok := set.Key(1)
	require.True(t, ok)
	require.False(t, jwk.IsUnsupportedKey(k1), "valid RSA key must not be detected")

	require.False(t, jwk.IsUnsupportedKey(nil), "nil key must not be detected")
}

func TestUnsupportedKeyRetention(t *testing.T) {
	t.Run("unknown kty is retained as placeholder", func(t *testing.T) {
		unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
		setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

		set, err := jwk.Parse(setJSON)
		require.NoError(t, err)
		require.Equal(t, 2, set.Len())

		k0, ok := set.Key(0)
		require.True(t, ok)
		uk, ok := k0.(jwk.UnsupportedKey)
		require.True(t, ok, "first key should be a jwk.UnsupportedKey")
		require.NotNil(t, uk.Reason(), "Reason() must carry the parse error")
		ukJSON, err := json.Marshal(uk)
		require.NoError(t, err)
		require.JSONEq(t, string(unknownEntry), string(ukJSON))

		kid, ok := uk.KeyID()
		require.True(t, ok)
		require.Equal(t, "foo1", kid)
		require.Equal(t, "FOO", uk.KeyType().String())

		k1, ok := set.Key(1)
		require.True(t, ok)
		_, isPlaceholder := k1.(jwk.UnsupportedKey)
		require.False(t, isPlaceholder, "the valid RSA key must not be a placeholder")
	})

	t.Run("AKP key with unregistered alg is retained (issue #2263)", func(t *testing.T) {
		// The mldsa extension is deliberately NOT imported, so ML-DSA-65
		// is not a registered algorithm. Core recognizes the AKP kty but
		// fails during unmarshal on the alg lookup — the exact v4 failure
		// mode from issue #2263.
		akpEntry := []byte(`{"kty":"AKP","alg":"ML-DSA-65","use":"sig","kid":"mldsa","pub":"dGVzdA"}`)
		setJSON := makeSetJSON(akpEntry, validRSAJWK(t, "rsa1"))

		set, err := jwk.Parse(setJSON)
		require.NoError(t, err)
		require.Equal(t, 2, set.Len())

		k0, ok := set.Key(0)
		require.True(t, ok)
		uk, ok := k0.(jwk.UnsupportedKey)
		require.True(t, ok)
		require.NotNil(t, uk.Reason())
		ukJSON, err := json.Marshal(uk)
		require.NoError(t, err)
		require.JSONEq(t, string(akpEntry), string(ukJSON))
		kid, ok := uk.KeyID()
		require.True(t, ok)
		require.Equal(t, "mldsa", kid)
	})

	t.Run("corrupt known-type entry becomes a placeholder", func(t *testing.T) {
		// Valid RSA shape but invalid base64 in "n".
		corruptEntry := []byte(`{"kty":"RSA","kid":"bad","n":"!!!not-base64!!!","e":"AQAB"}`)
		setJSON := makeSetJSON(corruptEntry, validRSAJWK(t, "rsa1"))

		set, err := jwk.Parse(setJSON)
		require.NoError(t, err)
		require.Equal(t, 2, set.Len())

		k0, ok := set.Key(0)
		require.True(t, ok)
		uk, ok := k0.(jwk.UnsupportedKey)
		require.True(t, ok)
		require.NotNil(t, uk.Reason())
	})
}

func TestUnsupportedKeyRoundTrip(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	set, err := jwk.Parse(setJSON)
	require.NoError(t, err)

	k0, ok := set.Key(0)
	require.True(t, ok)
	uk, ok := k0.(jwk.UnsupportedKey)
	require.True(t, ok)

	// The placeholder marshals back to the original entry's JSON.
	marshaled, err := json.Marshal(uk)
	require.NoError(t, err)
	require.JSONEq(t, string(unknownEntry), string(marshaled))

	// Marshaling the whole set re-emits the unknown entry unchanged.
	setOut, err := json.Marshal(set)
	require.NoError(t, err)
	require.Contains(t, string(setOut), `"kty":"FOO"`)
}

func TestUnsupportedKeyStrictMode(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	t.Run("per-call strict fails the whole set", func(t *testing.T) {
		_, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(true))
		require.Error(t, err)
	})

	t.Run("global strict fails the whole set", func(t *testing.T) {
		require.NoError(t, jwk.Settings(jwk.WithStrictKeySetParsing(true)))
		t.Cleanup(func() {
			require.NoError(t, jwk.Settings(jwk.WithStrictKeySetParsing(false)))
		})
		_, err := jwk.Parse(setJSON)
		require.Error(t, err)
	})
}

func TestUnsupportedKeyDropMode(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	set, err := jwk.Parse(setJSON, jwk.WithIgnoreParseError(true))
	require.NoError(t, err)
	require.Equal(t, 1, set.Len(), "the unparseable entry must be dropped, not retained")

	k0, ok := set.Key(0)
	require.True(t, ok)
	_, isPlaceholder := k0.(jwk.UnsupportedKey)
	require.False(t, isPlaceholder)
}

func TestUnsupportedKeyDuplicateKID(t *testing.T) {
	// The placeholder's best-effort kid collides with the RSA key's kid.
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"dup","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "dup"))

	_, err := jwk.Parse(setJSON, jwk.WithRejectDuplicateKID(true))
	require.Error(t, err, "a placeholder kid colliding with another key must be rejected")
}

func TestUnsupportedKeyPublicSetOf(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	set, err := jwk.Parse(setJSON)
	require.NoError(t, err)

	t.Run("errors by default", func(t *testing.T) {
		_, err := jwk.PublicSetOf(set)
		require.Error(t, err)
	})

	t.Run("omit drops the placeholder", func(t *testing.T) {
		pub, err := jwk.PublicSetOf(set, jwk.WithOmitUnsupportedKeys(true))
		require.NoError(t, err)
		require.Equal(t, 1, pub.Len())
		k0, ok := pub.Key(0)
		require.True(t, ok)
		_, isPlaceholder := k0.(jwk.UnsupportedKey)
		require.False(t, isPlaceholder)
	})
}

func TestUnsupportedKeyBareParseKey(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)

	t.Run("ParseKey on bare unknown kty is a hard error", func(t *testing.T) {
		_, err := jwk.ParseKey(unknownEntry)
		require.Error(t, err)
	})

	t.Run("Parse of a bare single JWK with unknown kty is a hard error", func(t *testing.T) {
		_, err := jwk.Parse(unknownEntry)
		require.Error(t, err)
	})
}

func TestUnsupportedKeyMethodContract(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","alg":"HS256","key_ops":["verify"],"x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	set, err := jwk.Parse(setJSON)
	require.NoError(t, err)
	k0, ok := set.Key(0)
	require.True(t, ok)
	uk, ok := k0.(jwk.UnsupportedKey)
	require.True(t, ok)

	t.Run("Thumbprint wraps Reason", func(t *testing.T) {
		_, err := uk.Thumbprint(crypto.SHA256)
		require.Error(t, err)
	})

	t.Run("PublicKey wraps Reason", func(t *testing.T) {
		_, err := uk.PublicKey()
		require.Error(t, err)
	})

	t.Run("Validate wraps Reason", func(t *testing.T) {
		require.Error(t, uk.Validate())
	})

	t.Run("Set and Remove error", func(t *testing.T) {
		require.Error(t, uk.Set(jwk.KeyIDKey, "other"))
		require.Error(t, uk.Remove(jwk.KeyIDKey))
	})

	t.Run("does not implement AsymmetricKey", func(t *testing.T) {
		_, ok := k0.(jwk.AsymmetricKey)
		require.False(t, ok)
	})

	t.Run("best-effort accessors reflect kty, kid and alg only", func(t *testing.T) {
		require.Equal(t, "FOO", uk.KeyType().String())
		kid, ok := uk.KeyID()
		require.True(t, ok)
		require.Equal(t, "foo1", kid)
		alg, ok := uk.Algorithm()
		require.True(t, ok)
		require.Equal(t, "HS256", alg.String())

		// Other standard members are not mirrored, even when present in
		// the entry; the raw JSON remains their only representation.
		_, ok = uk.KeyUsage()
		require.False(t, ok)
		_, ok = uk.KeyOps()
		require.False(t, ok)
	})
}

func TestUnsupportedKeyExport(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	set, err := jwk.Parse(setJSON)
	require.NoError(t, err)
	k0, ok := set.Key(0)
	require.True(t, ok)

	t.Run("Export errors on a placeholder", func(t *testing.T) {
		_, err := jwk.Export[any](k0)
		require.Error(t, err)
	})

	t.Run("ExportAll errors on a set with a placeholder", func(t *testing.T) {
		_, err := jwk.ExportAll[any](set)
		require.Error(t, err)
	})

	t.Run("AssignKeyID errors on a placeholder", func(t *testing.T) {
		require.Error(t, jwk.AssignKeyID(k0))
	})
}
