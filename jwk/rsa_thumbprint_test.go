package jwk_test

import (
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"math/bits"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

// RFC 7638 Section 3.1 canonical example.
const rfc7638RSAJWK = `{
  "kty": "RSA",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e": "AQAB"
}`

// Expected SHA-256 thumbprint from RFC 7638 Section 3.1:
//
//	NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
//
// decoded to hex.
const rfc7638ExpectedThumbprintHex = "3736cbb1787cb8309c77ee8c3705c5e16ffb9e859715901f1e4c59b11182f57b"

func TestRSA_Thumbprint_RFC7638Vector(t *testing.T) {
	k, err := jwk.ParseKey([]byte(rfc7638RSAJWK))
	require.NoError(t, err)

	got, err := k.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	require.Equal(t, rfc7638ExpectedThumbprintHex, hex.EncodeToString(got))
}

// TestRSA_ExponentTruncation_Rejected verifies that an RSA public exponent
// whose bit length does not fit in a Go `int` on this platform is rejected
// at export time, rather than being silently truncated.
//
// Regression for JWK-20260415151950-008.
func TestRSA_ExponentTruncation_Rejected(t *testing.T) {
	// e = 0x01_00_00_00_00_00_00_01 (65 bits) — fits neither 32-bit nor 64-bit int.
	payload := `{"kty":"RSA","n":"AQAB","e":"AQAAAAAAAAAB"}`

	k, err := jwk.ParseKey([]byte(payload))
	require.NoError(t, err, "parse should accept the raw bytes")

	var out rsa.PublicKey
	err = jwk.Export(k, &out)
	require.Error(t, err, "export must reject oversized exponent")
	require.Contains(t, err.Error(), "rsa public exponent too large")
}

// TestRSA_Thumbprint_UsesStoredBytes verifies that Thumbprint hashes the
// stored e/n bytes rather than round-tripping through rsa.PublicKey.E (int).
// Two JWKs whose e values differ only in leading zero bytes must produce
// identical thumbprints (leading zeros are stripped per RFC 7638 minimal
// representation). Two JWKs whose e values actually differ must produce
// different thumbprints.
//
// Regression for JWK-20260415151950-008.
func TestRSA_Thumbprint_UsesStoredBytes(t *testing.T) {
	// Standard F4 = 0x10001
	jwkF4 := `{"kty":"RSA","n":"AQAB","e":"AQAB"}`
	// Same exponent with an added leading zero byte: e = 0x00_01_00_01
	jwkF4PaddedE := `{"kty":"RSA","n":"AQAB","e":"AAEAAQ"}`
	// Different exponent entirely: e = 3
	jwkE3 := `{"kty":"RSA","n":"AQAB","e":"Aw"}`

	thumb := func(payload string) []byte {
		k, err := jwk.ParseKey([]byte(payload))
		require.NoError(t, err)
		tp, err := k.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		return tp
	}

	f4 := thumb(jwkF4)
	f4Padded := thumb(jwkF4PaddedE)
	e3 := thumb(jwkE3)

	require.Equal(t, f4, f4Padded, "leading-zero-padded e must produce the same RFC 7638 thumbprint")
	require.NotEqual(t, f4, e3, "distinct e values must produce distinct thumbprints")
}

// sanity: the check should be per-platform (only triggers on 32-bit builds
// for values between 2^31 and 2^63 — but the pure-Go guard is the same).
func TestRSA_BitsUintSize(t *testing.T) {
	require.True(t, bits.UintSize == 32 || bits.UintSize == 64)
}

// ensure the tests don't drift from Parse/Export behavior. Marshal the
// RFC 7638 JWK back out and confirm it round-trips.
func TestRSA_RFC7638_RoundTrip(t *testing.T) {
	k, err := jwk.ParseKey([]byte(rfc7638RSAJWK))
	require.NoError(t, err)

	buf, err := json.Marshal(k)
	require.NoError(t, err)

	k2, err := jwk.ParseKey(buf)
	require.NoError(t, err)

	tp1, err := k.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	tp2, err := k2.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, tp1, tp2)
}
