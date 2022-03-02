package jwk

import (
	"crypto/x509"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/internal/json"

	"github.com/lestrrat-go/jwx/v2/internal/base64"
)

func (c CertificateChain) MarshalJSON() ([]byte, error) {
	certs := c.Get()
	encoded := make([]string, len(certs))
	for i := 0; i < len(certs); i++ {
		encoded[i] = base64.EncodeToStringStd(certs[i].Raw)
	}
	return json.Marshal(encoded)
}

func (c *CertificateChain) UnmarshalJSON(buf []byte) error {
	var list []string
	if err := json.Unmarshal(buf, &list); err != nil {
		return fmt.Errorf(`failed to unmarshal JSON into []string: %w`, err)
	}

	var tmp CertificateChain
	if err := tmp.Accept(list); err != nil {
		return err
	}

	*c = tmp
	return nil
}

func (c CertificateChain) Get() []*x509.Certificate {
	return c.certs
}

func (c *CertificateChain) Accept(v interface{}) error {
	var list []string

	switch x := v.(type) {
	case string:
		list = []string{x}
	case []interface{}:
		list = make([]string, len(x))
		for i, e := range x {
			if es, ok := e.(string); ok {
				list[i] = es
				continue
			}
			return fmt.Errorf(`invalid list element type: expected string, got %T at element %d`, e, i)
		}
	case []string:
		list = x
	case CertificateChain:
		certs := make([]*x509.Certificate, len(x.certs))
		copy(certs, x.certs)
		*c = CertificateChain{
			certs: certs,
		}
		return nil
	default:
		return fmt.Errorf(`invalid type for CertificateChain: %T`, v)
	}

	certs := make([]*x509.Certificate, len(list))
	for i, e := range list {
		buf, err := base64.DecodeString(e)
		if err != nil {
			return fmt.Errorf(`failed to base64 decode list element: %w`, err)
		}
		cert, err := x509.ParseCertificate(buf)
		if err != nil {
			return fmt.Errorf(`failed to parse certificate: %w`, err)
		}
		certs[i] = cert
	}

	*c = CertificateChain{
		certs: certs,
	}
	return nil
}
