package cert_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	goldenCert, err := cert.Parse(certBytes)
	if !assert.NoError(t, err, `x509.ParseCertificate should succeed`) {
		return
	}

	testcases := []struct {
		Name string
		Data []byte
	}{
		{
			Name: `proper base64 in ASN.1 DER`,
			Data: certBytes,
		},
		{
			Name: `proper base64 in ASN.1 DER, but with markers`,
			Data: append(append([]byte("----- BEGIN CERTIFICATE -----\n"), certBytes...), []byte("\n----- END CERTIFICATE -----")...),
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
}
