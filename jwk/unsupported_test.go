package jwk_test

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwk"
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

// TestUnsupportedKeyDefaultUnchanged is the regression guard for the v3
// promise: with no options, a set containing one unparseable entry still
// fails the whole set, exactly as older v3 releases did.
func TestUnsupportedKeyDefaultUnchanged(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	_, err := jwk.Parse(setJSON)
	require.Error(t, err, "default (strict) must fail the whole set on an unparseable entry")
}

func TestIsUnsupportedKey(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
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

		set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
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

	t.Run("AKP key with unknown kty is retained (issue #2263)", func(t *testing.T) {
		// v3 does not know the AKP key type at all, so this entry fails
		// on the unknown kty — the exact complaint in issue #2263 for a
		// post-quantum key published alongside classical keys.
		akpEntry := []byte(`{"kty":"AKP","alg":"ML-DSA-65","use":"sig","kid":"mldsa","pub":"dGVzdA"}`)
		setJSON := makeSetJSON(akpEntry, validRSAJWK(t, "rsa1"))

		// Default: whole-set failure (the issue's exact complaint).
		_, err := jwk.Parse(setJSON)
		require.Error(t, err, "default must fail the whole set on an AKP entry")

		// Opt in to retention: placeholder is kept, RSA key stays usable.
		set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
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

		k1, ok := set.Key(1)
		require.True(t, ok)
		_, isPlaceholder := k1.(jwk.UnsupportedKey)
		require.False(t, isPlaceholder, "the valid RSA key must remain usable")
	})

	t.Run("corrupt known-type entry becomes a placeholder", func(t *testing.T) {
		// Valid RSA shape but invalid base64 in "n".
		corruptEntry := []byte(`{"kty":"RSA","kid":"bad","n":"!!!not-base64!!!","e":"AQAB"}`)
		setJSON := makeSetJSON(corruptEntry, validRSAJWK(t, "rsa1"))

		set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
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

	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
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

	t.Run("explicit per-call strict fails the whole set", func(t *testing.T) {
		_, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(true))
		require.Error(t, err)
	})

	t.Run("global strict can be turned off and back on", func(t *testing.T) {
		// Default global is strict=true; verify a per-call override wins,
		// then that Configure can flip the global default.
		jwk.Configure(jwk.WithStrictKeySetParsing(false))
		t.Cleanup(func() {
			jwk.Configure(jwk.WithStrictKeySetParsing(true))
		})
		set, err := jwk.Parse(setJSON)
		require.NoError(t, err, "global override to non-strict must retain the placeholder")
		require.Equal(t, 2, set.Len())

		_, err = jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(true))
		require.Error(t, err, "per-call strict must override the non-strict global")
	})
}

func TestUnsupportedKeyDropMode(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	t.Run("ignore alone drops under the default strict setting", func(t *testing.T) {
		// WithIgnoreParseError(true) is checked before the strict flag,
		// so it selects drop mode on its own — no need to also pass
		// WithStrictKeySetParsing(false).
		set, err := jwk.Parse(setJSON, jwk.WithIgnoreParseError(true))
		require.NoError(t, err)
		require.Equal(t, 1, set.Len(), "the unparseable entry must be dropped")
	})

	t.Run("ignore wins over non-strict retention", func(t *testing.T) {
		set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false), jwk.WithIgnoreParseError(true))
		require.NoError(t, err)
		require.Equal(t, 1, set.Len(), "the unparseable entry must be dropped, not retained")

		k0, ok := set.Key(0)
		require.True(t, ok)
		_, isPlaceholder := k0.(jwk.UnsupportedKey)
		require.False(t, isPlaceholder)
	})
}

// keyWithReasonMethod imitates a third-party jwk.Key implementation that
// happens to expose a Reason() error method. Because the UnsupportedKey
// interface is sealed with an unexported marker method, such a key must
// never be mistaken for a placeholder.
type keyWithReasonMethod struct {
	jwk.Key
}

func (keyWithReasonMethod) Reason() error { return nil }

func TestThirdPartyKeyWithReasonMethodIsNotAPlaceholder(t *testing.T) {
	base, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	wrapped := keyWithReasonMethod{Key: base}

	require.False(t, jwk.IsUnsupportedKey(wrapped),
		"a third-party key with a Reason() method must not be detected as a placeholder")
	require.NoError(t, jwk.AssignKeyID(wrapped),
		"AssignKeyID must treat the wrapper as a normal key")
	require.True(t, wrapped.Has(jwk.KeyIDKey), "AssignKeyID must have set a kid")
}

func TestUnsupportedKeyDuplicateKID(t *testing.T) {
	// The placeholder's best-effort kid collides with the RSA key's kid.
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"dup","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "dup"))

	_, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false), jwk.WithRejectDuplicateKID(true))
	require.Error(t, err, "a placeholder kid colliding with another key must be rejected")
}

func TestUnsupportedKeyPublicSetOf(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
	require.NoError(t, err)

	t.Run("errors by default naming kty, kid and index", func(t *testing.T) {
		_, err := jwk.PublicSetOf(set)
		require.Error(t, err)
		require.Contains(t, err.Error(), `kty="FOO"`, "error must name the kty")
		require.Contains(t, err.Error(), `kid="foo1"`, "error must name the kid")
		require.Contains(t, err.Error(), `index=0`, "error must name the index")
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

	t.Run("WithStrictKeySetParsing(false) does not make ParseKey retain", func(t *testing.T) {
		// Placeholders are set-only; the option is ignored by ParseKey,
		// which still hard-errors on an unparseable bare key.
		_, err := jwk.ParseKey(unknownEntry, jwk.WithStrictKeySetParsing(false))
		require.Error(t, err)
	})

	t.Run("Parse of a bare single JWK with unknown kty is a hard error", func(t *testing.T) {
		_, err := jwk.Parse(unknownEntry, jwk.WithStrictKeySetParsing(false))
		require.Error(t, err)
	})
}

func TestUnsupportedKeyMethodContract(t *testing.T) {
	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","alg":"HS256","key_ops":["verify"],"x":"dGVzdA"}`)
	setJSON := makeSetJSON(unknownEntry, validRSAJWK(t, "rsa1"))

	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
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

	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
	require.NoError(t, err)
	k0, ok := set.Key(0)
	require.True(t, ok)

	t.Run("Export errors on a placeholder", func(t *testing.T) {
		var raw any
		require.Error(t, jwk.Export(k0, &raw))
	})

	t.Run("AssignKeyID errors on a placeholder naming kty and kid", func(t *testing.T) {
		err := jwk.AssignKeyID(k0)
		require.Error(t, err)
		require.Contains(t, err.Error(), `kty="FOO"`, "error must name the kty")
		require.Contains(t, err.Error(), `kid="foo1"`, "error must name the kid")
	})
}
