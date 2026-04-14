package cert

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/tokens"
)

// Chain represents a certificate chain as used in the `x5c` field of
// various objects within JOSE.
//
// It stores the certificates as a list of base64 encoded []byte
// sequence. By definition these values must PKIX encoded.
type Chain struct {
	certificates [][]byte
}

func (cc Chain) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(tokens.OpenSquareBracket)
	for i, cert := range cc.certificates {
		if i > 0 {
			buf.WriteByte(tokens.Comma)
		}
		buf.WriteByte('"')
		buf.Write(cert)
		buf.WriteByte('"')
	}
	buf.WriteByte(tokens.CloseSquareBracket)
	return buf.Bytes(), nil
}

func (cc *Chain) UnmarshalJSON(data []byte) error {
	var tmp []string
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf(`failed to unmarshal certificate chain: %w`, err)
	}

	certs := make([][]byte, len(tmp))
	for i, cert := range tmp {
		certs[i] = []byte(cert)
	}
	cc.certificates = certs
	return nil
}

// Get returns the n-th ASN.1 DER + base64 encoded certificate
// stored. `false` will be returned in the second argument if
// the corresponding index is out of range.
func (cc *Chain) Get(index int) ([]byte, bool) {
	if index < 0 || index >= len(cc.certificates) {
		return nil, false
	}

	return cc.certificates[index], true
}

// Len returns the number of certificates stored in this Chain
func (cc *Chain) Len() int {
	return len(cc.certificates)
}

func (cc *Chain) AddString(der string) error {
	return cc.Add([]byte(der))
}

func (cc *Chain) Add(der []byte) error {
	der = bytes.TrimSpace(der)
	// Accept a PEM-encoded CERTIFICATE block and convert it to the
	// base64(DER) form that x5c requires.
	if block, _ := pem.Decode(der); block != nil && block.Type == "CERTIFICATE" {
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(block.Bytes)))
		base64.StdEncoding.Encode(encoded, block.Bytes)
		cc.certificates = append(cc.certificates, encoded)
		return nil
	}
	cc.certificates = append(cc.certificates, der)
	return nil
}
