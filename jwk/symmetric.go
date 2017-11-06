package jwk

import (
	"crypto"
	"fmt"

	"github.com/pkg/errors"
)

// Materialize returns the octets for this symmetric key.
// Since this is a symmetric key, this just calls Octets
func (s SymmetricKey) Materialize() (interface{}, error) {
	return s.Octets(), nil
}

// Octets returns the octets in the key
func (s SymmetricKey) Octets() []byte {
	return s.Key
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (s SymmetricKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	const tmpl = `{"k":"%s","kty":"oct"}`
	k64, err := s.Key.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, `failed to base64 encode symmetric key`)
	}

	v := fmt.Sprintf(tmpl, k64)
	h := hash.New()
	h.Write([]byte(v))
	return h.Sum(nil), nil
}
