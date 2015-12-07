package jwk

import (
	"crypto"
	"fmt"
)

func (s SymmetricKey) Materialize() (interface{}, error) {
	return s.Octets(), nil
}

func (s SymmetricKey) Octets() []byte {
	return s.Key
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (s SymmetricKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	const tmpl = `{"k":"%s","kty":"oct"}`
	k64, err := s.Key.Base64Encode()
	if err != nil {
		return nil, err
	}

	v := fmt.Sprintf(tmpl, k64)
	h := hash.New()
	h.Write([]byte(v))
	return h.Sum(nil), nil
}
