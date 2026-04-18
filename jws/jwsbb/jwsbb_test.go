package jwsbb_test

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
	"io"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
	"github.com/stretchr/testify/require"
)

// endlessReader is a non-finite io.Reader that fills buf with b indefinitely
// and never returns EOF. It is intentionally not a
// *bytes.Reader/*bytes.Buffer/*strings.Reader so that
// jwxio.ReadAllFromFiniteSource classifies it as non-finite.
type endlessReader struct{ b byte }

func (r *endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

func TestSplitCompactReaderNonFiniteSizeCap(t *testing.T) {
	t.Parallel()
	//nolint:dogsled // SplitCompactReader returns 4 values; we only need err here
	_, _, _, err := jwsbb.SplitCompactReader(&endlessReader{b: 'X'})
	require.Error(t, err, "SplitCompactReader should fail on oversized non-finite input")
	require.ErrorIs(t, err, jwsbb.InputTooLargeError(), "error should be InputTooLargeError")
}

func TestSplitCompactReaderLimitedReaderLargeN(t *testing.T) {
	t.Parallel()

	// A *io.LimitedReader with a very large N passes the finite-source
	// type check. Without a size cap on the finite path, io.ReadAll would
	// attempt to allocate N bytes (DoS via OOM). Verify that
	// SplitCompactReader caps the read on the finite path too.
	const oversized = 11 * 1024 * 1024 // > maxSplitCompactReaderSize (10 MiB)
	rdr := &io.LimitedReader{R: &endlessReader{b: 'X'}, N: oversized}

	//nolint:dogsled
	_, _, _, err := jwsbb.SplitCompactReader(rdr)
	require.Error(t, err, "SplitCompactReader should reject oversized LimitedReader")
	require.ErrorIs(t, err, jwsbb.InputTooLargeError(), "error should be InputTooLargeError")
}

const sampleHeader = "eyJmb28iOiJiYXIifQ" // Base64URL of {"foo":"bar"}

func TestHMAC(t *testing.T) {
	t.Parallel()
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
			signBuffer := jwsbb.SignBuffer(nil, header, payload, encoder, tc.encodePayload)
			sig, err := jwsbb.SignHMAC(key, signBuffer, tc.hfunc)
			require.NoError(t, err, "SignHMAC should not return error")
			require.NoError(t, jwsbb.VerifyHMAC(key, signBuffer, sig, tc.hfunc), "VerifyHMAC should succeed for a valid signature")
			require.Error(t, jwsbb.VerifyHMAC(key, signBuffer, sig[:len(sig)-1], tc.hfunc), "VerifyHMAC should fail for an invalid signature")
		})
	}

	const examplePayload = `{"iss":"joe",` + "\r\n" + ` "exp":1300819380,` + "\r\n" + ` "http://example.com/is_root":true}`
	t.Run("RFC Example", func(t *testing.T) {
		t.Parallel()
		const hdr = `{"typ":"JWT",` + "\r\n" + ` "alg":"HS256"}`
		const hmacKey = `AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow`
		const expected = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`

		hmacKeyDecoded, err := base64.DecodeString(hmacKey)
		require.NoError(t, err, "decoding key should succeed")

		signBuffer := jwsbb.SignBuffer(nil, []byte(hdr), []byte(examplePayload), base64.DefaultEncoder(), true)
		signature, err := jwsbb.SignHMAC(hmacKeyDecoded, signBuffer, sha256.New)
		require.NoError(t, err, "SignHMAC should succeed")

		buf := pool.ByteSlice().Get()
		buf, err = jwsbb.JoinCompact(buf, []byte(hdr), []byte(examplePayload), signature, base64.DefaultEncoder(), true)
		require.NoError(t, err, "JoinCompact should succeed")
		defer pool.ByteSlice().Put(buf)
		require.Equal(t, expected, string(buf), "serialized output should match expected value")
	})
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

			signBuffer := jwsbb.SignBuffer(nil, header, payload, encoding, tc.encodePayload)
			sig, err := jwsbb.SignRSA(priv, signBuffer, tc.h, tc.pss, nil)
			require.NoError(t, err, "SignRSA should not return error")
			require.NoError(t, jwsbb.VerifyRSA(&priv.PublicKey, signBuffer, sig, tc.h, tc.pss), "VerifyRSA should succeed for a valid signature")
			require.Error(t, jwsbb.VerifyRSA(&priv.PublicKey, signBuffer, sig[:len(sig)-1], tc.h, tc.pss), "VerifyRSA should fail for an invalid signature")
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

			signBuffer := jwsbb.SignBuffer(nil, header, payload, encoder, tc.encodePayload)
			sig, err := jwsbb.SignECDSA(priv, signBuffer, tc.h, nil)
			require.NoError(t, err, "SignECDSA should not return error")
			require.NoError(t, jwsbb.VerifyECDSA(&priv.PublicKey, signBuffer, sig, tc.h), "VerifyECDSA should succeed for a valid signature")
			require.Error(t, jwsbb.VerifyECDSA(&priv.PublicKey, signBuffer, sig[:len(sig)-1], tc.h), "VerifyECDSA should fail for an invalid signature")
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

			signBuffer := jwsbb.SignBuffer(nil, header, payload, encoding, tc.encodePayload)
			sig, err := jwsbb.SignEdDSA(priv, signBuffer)
			require.NoError(t, err, "SignEdDSA should not return error")
			require.NoError(t, jwsbb.VerifyEdDSA(pub, signBuffer, sig), "VerifyEdDSA should succeed for a valid signature")
			require.Error(t, jwsbb.VerifyEdDSA(pub, signBuffer, sig[:len(sig)-1]), "VerifyEdDSA should fail for an invalid signature")
		})
	}
}
