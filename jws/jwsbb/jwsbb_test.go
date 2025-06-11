package jwsbb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/stretchr/testify/require"
)

const sampleHeader = "eyJmb28iOiJiYXIifQ" // Base64URL of {"foo":"bar"}

func TestHMAC(t *testing.T) {
	tests := []struct {
		alg           string
		hfunc         func() hash.Hash
		encodePayload bool
	}{
		{"HS256", sha256.New, true},
		{"HS384", sha512.New384, true},
		{"HS512", sha512.New, true},
		{"HS256", sha256.New, false},
		{"HS384", sha512.New384, false},
		{"HS512", sha512.New, false},
	}

	encoder := base64.DefaultEncoder()
	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			payload := []byte("hello")
			key := []byte("secretkey")
			header := []byte(sampleHeader)

			sig, err := SignHMAC(payload, header, tc.hfunc, encoder, tc.encodePayload, key)
			require.NoError(t, err, "SignHMAC should not return error")
			require.NoError(t, VerifyHMAC(payload, header, sig, tc.hfunc, encoder, tc.encodePayload, key), "VerifyHMAC should succeed for a valid signature")
			require.Error(t, VerifyHMAC(payload, header, sig[:len(sig)-1], tc.hfunc, encoder, tc.encodePayload, key), "VerifyHMAC should fail for an invalid signature")
		})
	}
}

func TestRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "RSA key generation should not error")

	testcases := []struct {
		name          string
		h             crypto.Hash
		pss           bool
		encodePayload bool
	}{
		{"RS256", crypto.SHA256, false, true},
		{"RS384", crypto.SHA384, false, true},
		{"RS512", crypto.SHA512, false, true},
		{"PS256", crypto.SHA256, true, true},
		{"PS384", crypto.SHA384, true, true},
		{"PS512", crypto.SHA512, true, true},
		{"RS256_no_encode", crypto.SHA256, false, false},
		{"RS384_no_encode", crypto.SHA384, false, false},
		{"RS512_no_encode", crypto.SHA512, false, false},
		{"PS256_no_encode", crypto.SHA256, true, false},
		{"PS384_no_encode", crypto.SHA384, true, false},
		{"PS512_no_encode", crypto.SHA512, true, false},
	}

	encoding := base64.DefaultEncoder()
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("hello")
			header := []byte(sampleHeader)

			sig, err := SignRSA(payload, header, tc.h, tc.pss, encoding, tc.encodePayload, priv)
			require.NoError(t, err, "SignRSA should not return error")
			require.NoError(t, VerifyRSA(payload, header, sig, tc.h, tc.pss, encoding, tc.encodePayload, &priv.PublicKey), "VerifyRSA should succeed for a valid signature")
			require.Error(t, VerifyRSA(payload, header, sig[:len(sig)-1], tc.h, tc.pss, encoding, tc.encodePayload, &priv.PublicKey), "VerifyRSA should fail for an invalid signature")
		})
	}
}

func TestECDSA(t *testing.T) {
	table := []struct {
		name          string
		curve         elliptic.Curve
		h             crypto.Hash
		encodePayload bool
	}{
		{"P256_SHA256_b64=true", elliptic.P256(), crypto.SHA256, true},
		{"P384_SHA384_b64=true", elliptic.P384(), crypto.SHA384, true},
		{"P521_SHA512_b64=true", elliptic.P521(), crypto.SHA512, true},
		{"P256_SHA256", elliptic.P256(), crypto.SHA256, false},
		{"P384_SHA384", elliptic.P384(), crypto.SHA384, false},
		{"P521_SHA512", elliptic.P521(), crypto.SHA512, false},
	}

	encoder := base64.DefaultEncoder()
	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("hello")
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err, "ECDSA key generation should not error")

			// prepare placeholder header
			header := []byte(sampleHeader)

			sig, err := SignECDSA(payload, header, tc.h, encoder, tc.encodePayload, priv)
			require.NoError(t, err, "SignECDSA should not return error")
			require.NoError(t, VerifyECDSA(payload, header, sig, tc.h, encoder, tc.encodePayload, &priv.PublicKey), "VerifyECDSA should succeed for a valid signature")
			require.Error(t, VerifyECDSA(payload, header, sig[:len(sig)-1], tc.h, encoder, tc.encodePayload, &priv.PublicKey), "VerifyECDSA should fail for an invalid signature")
		})
	}
}

func TestEdDSA(t *testing.T) {
	testcases := []struct {
		name          string
		encodePayload bool
	}{
		{"Ed25519_b64=true", true},
		{"Ed25519_b64=false", false},
	}
	encoding := base64.DefaultEncoder()

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("hello")
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err, "EdDSA key generation should not error")

			// prepare placeholder header
			header := []byte(sampleHeader)

			sig, err := SignEdDSA(payload, header, encoding, tc.encodePayload, priv)
			require.NoError(t, err, "SignEdDSA should not return error")
			require.NoError(t, VerifyEdDSA(payload, header, sig, encoding, tc.encodePayload, pub), "VerifyEdDSA should succeed for a valid signature")
			require.Error(t, VerifyEdDSA(payload, header, sig[:len(sig)-1], encoding, tc.encodePayload, pub), "VerifyEdDSA should fail for an invalid signature")
		})
	}
}
