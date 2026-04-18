package cert_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/stretchr/testify/require"
)

const (
	testDefaultMaxChainLength     = 10
	testDefaultMaxCertificateSize = 256 * 1024
)

func restoreCertSettings() {
	cert.Settings(
		cert.WithMaxChainLength(testDefaultMaxChainLength),
		cert.WithMaxCertificateSize(testDefaultMaxCertificateSize),
	)
}

var certBytes = []byte(`MIICdDCCAd2gAwIBAgIUEpq1vvAyaiEKhgEE/UKykUcnXi4wDQYJKoZIhvcNAQEL
BQAwTDELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMREwDwYDVQQHDAhSb3Bw
b25naTEMMAoGA1UECgwDSldYMQwwCgYDVQQDDANKV1gwHhcNMjIwMzEzMTMzOTIy
WhcNMjMwMzEzMTMzOTIyWjBMMQswCQYDVQQGEwJKUDEOMAwGA1UECAwFVG9reW8x
ETAPBgNVBAcMCFJvcHBvbmdpMQwwCgYDVQQKDANKV1gxDDAKBgNVBAMMA0pXWDCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwHm1AyeTpFWghI3PRTitSBMmbXqQ
ccrmK+4RZkp4JRhRXH6dc6O0JvsesoMmONegeU3c/FNU7ZTdaXJHGZCo4IUil0gv
rJRn52LAvCkodNwKG80+xHvGXix3LEaiTPbBmqGCttx5Q+2WsiBjZPHtQU2kOVs4
k90F++pImEd7Xl8CAwEAAaNTMFEwHQYDVR0OBBYEFN78aX+uEXMpDrZhtEY2e/vR
jdgSMB8GA1UdIwQYMBaAFN78aX+uEXMpDrZhtEY2e/vRjdgSMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADgYEAsrNkfe2+E9fpFkmIYPkxiOGMo0d6edlV
Q0fW17ZhS1fuM3eQJr61IJvZ4hEP2KjsOEJzRvptxkpVFiDOZf8DbkUVNpeWxorK
gPt3f4fzO4SIXu7fG89QkR5TJs6lxyZsr1V/IumL4LSx04LhIvMhHiUbbyVHgN8B
KpDY+K+bsqw=`)

func TestChain(t *testing.T) {
	restoreCertSettings()
	defer restoreCertSettings()

	goldenCert, err := cert.Parse(certBytes)
	require.NoError(t, err, `x509.ParseCertificate should succeed`)

	testcases := []struct {
		Name string
		Data []byte
	}{
		{
			Name: `proper base64 in ASN.1 DER`,
			Data: certBytes,
		},
		{
			Name: `PEM block with RFC 7468 markers`,
			Data: append(append([]byte("-----BEGIN CERTIFICATE-----\n"), certBytes...), []byte("\n-----END CERTIFICATE-----")...),
		},
		{
			Name: `PEM block with trailing newline`,
			Data: append(append([]byte("-----BEGIN CERTIFICATE-----\n"), certBytes...), []byte("\n-----END CERTIFICATE-----\n")...),
		},
	}

	var chain cert.Chain
	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			require.NoError(t, chain.Add(tc.Data), `chain.Add should succeed`)
		})
	}

	require.Equal(t, len(testcases), chain.Len(), `certificates in chain should match`)

	for i := range chain.Len() {
		der, ok := chain.Get(i)
		require.True(t, ok, `chain.Get(%d) should succeed`, i)

		c, err := cert.Parse(der)
		require.NoError(t, err, `cert.Parse should match`)
		require.True(t, c.Equal(goldenCert), `certificates should match`)
	}

	for _, i := range []int{-1, chain.Len()} {
		_, ok := chain.Get(i)
		require.False(t, ok, `out of bounds should properly error`)
	}

	t.Run(`MarshalJSON round-trip`, func(t *testing.T) {
		// Regression for CERT-002: MarshalJSON must produce valid JSON
		// even when Add was called with a multi-line base64 literal.
		encoded, err := json.Marshal(&chain)
		require.NoError(t, err, `json.Marshal(chain) should succeed`)

		var back []string
		require.NoError(t, json.Unmarshal(encoded, &back), `marshaled chain must be valid JSON`)
		require.Equal(t, chain.Len(), len(back), `round-trip should preserve length`)

		for i, s := range back {
			// The serialized string must be single-line base64 with no whitespace.
			der, err := base64.StdEncoding.DecodeString(s)
			require.NoError(t, err, `entry %d must be valid base64`, i)
			parsed, err := cert.Parse([]byte(s))
			require.NoError(t, err, `entry %d must round-trip through cert.Parse`, i)
			require.True(t, parsed.Equal(goldenCert), `entry %d must match golden cert`, i)
			require.NotEmpty(t, der)
		}
	})
}

func TestChainAddRejectsInvalid(t *testing.T) {
	restoreCertSettings()
	defer restoreCertSettings()

	// Regression for CERT-002: Add must reject input that would produce
	// invalid JSON or enable JSON injection when later marshaled.
	testcases := []struct {
		Name string
		Data []byte
	}{
		{Name: `quote injection`, Data: []byte(`abc","injected":"x`)},
		{Name: `raw garbage`, Data: []byte(`not base64 at all !!!`)},
		{Name: `control characters`, Data: []byte("ab\x00cd")},
		{Name: `valid base64 but not certificate`, Data: []byte(base64.StdEncoding.EncodeToString([]byte(`not a certificate`)))},
	}
	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			var chain cert.Chain
			require.Error(t, chain.Add(tc.Data), `Add should reject invalid input`)
			require.Equal(t, 0, chain.Len(), `failed Add must not mutate chain`)
		})
	}
}

func TestChainUnmarshalJSONRejectsInvalidCertificate(t *testing.T) {
	restoreCertSettings()
	defer restoreCertSettings()

	var chain cert.Chain
	require.NoError(t, chain.Add(certBytes), `chain.Add should succeed`)

	buf, err := json.Marshal([]string{base64.StdEncoding.EncodeToString([]byte(`not a certificate`))})
	require.NoError(t, err, `json.Marshal should succeed`)

	err = json.Unmarshal(buf, &chain)
	require.Error(t, err, `json.Unmarshal should fail`)
	require.Equal(t, 1, chain.Len(), `failed unmarshal must not mutate the existing chain`)
}

func TestChainRejectsDefaultMaxChainLength(t *testing.T) {
	restoreCertSettings()
	defer restoreCertSettings()

	var chain cert.Chain
	for range testDefaultMaxChainLength {
		require.NoError(t, chain.Add(certBytes), `chain.Add should succeed`)
	}

	require.Error(t, chain.Add(certBytes), `chain.Add should enforce the default max chain length`)
	require.Equal(t, testDefaultMaxChainLength, chain.Len(), `failed Add must not mutate chain`)
}

func TestChainAllowsUnlimitedChainLength(t *testing.T) {
	restoreCertSettings()
	defer restoreCertSettings()

	cert.Settings(cert.WithMaxChainLength(0))

	var chain cert.Chain
	for range testDefaultMaxChainLength + 1 {
		require.NoError(t, chain.Add(certBytes), `chain.Add should succeed when the limit is disabled`)
	}

	require.Equal(t, testDefaultMaxChainLength+1, chain.Len(), `all certificates should be accepted`)
}

func TestChainRejectsDefaultMaxCertificateSize(t *testing.T) {
	restoreCertSettings()
	defer restoreCertSettings()

	oversized := make([]byte, testDefaultMaxCertificateSize+1)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(oversized)))
	base64.StdEncoding.Encode(encoded, oversized)

	var chain cert.Chain
	require.Error(t, chain.Add(encoded), `chain.Add should enforce the default max certificate size`)
	require.Equal(t, 0, chain.Len(), `failed Add must not mutate chain`)
}

func TestChainAllowsUnlimitedCertificateSize(t *testing.T) {
	restoreCertSettings()
	defer restoreCertSettings()

	cert.Settings(cert.WithMaxCertificateSize(1))

	var chain cert.Chain
	require.Error(t, chain.Add(certBytes), `chain.Add should respect a small configured max certificate size`)

	cert.Settings(cert.WithMaxCertificateSize(0))
	require.NoError(t, chain.Add(certBytes), `chain.Add should succeed when the size limit is disabled`)
	require.Equal(t, 1, chain.Len(), `the certificate should be appended`)
}
