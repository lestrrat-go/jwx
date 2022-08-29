package cert_test

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/stretchr/testify/assert"
)

func parseCIDR(s string) *net.IPNet {
	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return net
}

func parseURI(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}

func TestCert(t *testing.T) {
	privkey, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaKey`) {
		return
	}

	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	oidExtensionSubjectKeyID := []int{2, 5, 29, 14}

	commonName := "test.example.com"
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), // SerialNumbers must be non-negative since go1.19
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Σ Acme Co"},
			Country:      []string{"US"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		SignatureAlgorithm: x509.SHA384WithRSA,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		URIs:           []*url.URL{parseURI("https://foo.com/wibble#foo")},

		PolicyIdentifiers:       []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains:     []string{".example.com", "example.com"},
		ExcludedDNSDomains:      []string{"bar.example.com"},
		PermittedIPRanges:       []*net.IPNet{parseCIDR("192.168.1.1/16"), parseCIDR("1.2.3.4/8")},
		ExcludedIPRanges:        []*net.IPNet{parseCIDR("2001:db8::/48")},
		PermittedEmailAddresses: []string{"foo@example.com"},
		ExcludedEmailAddresses:  []string{".example.com", "example.com"},
		PermittedURIDomains:     []string{".bar.com", "bar.com"},
		ExcludedURIDomains:      []string{".bar2.com", "bar2.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyID,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}

	b64, err := cert.Create(rand.Reader, &template, &template, &privkey.PublicKey, privkey)
	if !assert.NoError(t, err, `cert.Certificate should succeed`) {
		return
	}

	_, err = cert.Parse(b64)
	if !assert.NoError(t, err, `cert.Parse should succeed`) {
		return
	}
}
