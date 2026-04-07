package asmbase64_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"encoding/json"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"

	// Import for side-effect registration of the asm base64 backend
	_ "github.com/jwx-go/asmbase64"
)

// TestJWKRoundTrip verifies that JWK serialization and parsing work
// correctly with the assembly-optimized base64 backend.
func TestJWKRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, `ecdsa.GenerateKey should succeed`)

	jwkKey, err := jwk.Import[jwk.Key](key)
	require.NoError(t, err, `jwk.Import should succeed`)

	buf, err := json.Marshal(jwkKey)
	require.NoError(t, err, `json.Marshal should succeed`)

	parsed, err := jwk.ParseKey[jwk.Key](buf)
	require.NoError(t, err, `jwk.ParseKey should succeed`)

	// Verify the key fields survived the round-trip through asm base64
	origDV, ok := jwkKey.Field("d")
	require.True(t, ok, `original key.Field("d") should succeed`)
	origD := origDV.([]byte)
	parsedDV, ok := parsed.Field("d")
	require.True(t, ok, `parsed key.Field("d") should succeed`)
	parsedD := parsedDV.([]byte)
	require.Equal(t, origD, parsedD, `"d" field should match after round-trip`)
}

// TestJWSRoundTrip verifies that JWS sign/verify work correctly with the
// assembly-optimized base64 backend.
func TestJWSRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, `ecdsa.GenerateKey should succeed`)

	payload := []byte("Hello, World! Testing asm base64 backend.")

	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key))
	require.NoError(t, err, `jws.Sign should succeed`)

	verified, err := jws.Verify(signed, jws.WithKey(jwa.ES256(), &key.PublicKey))
	require.NoError(t, err, `jws.Verify should succeed`)
	require.Equal(t, payload, verified, `verified payload should match`)
}
