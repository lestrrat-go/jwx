package jwk

import (
	"crypto"
	"fmt"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

func newSymmetricKey(octets []byte) (*SymmetricKey, error) {
	if len(octets) == 0 {
		return nil, errors.New(`non-empty []byte key required`)
	}

	var key SymmetricKey

	if err := key.Set(KeyTypeKey, jwa.OctetSeq); err != nil {
		return nil, errors.Wrapf(err, `faild set %s for symmetric key`, KeyTypeKey)
	}
	key.octets = octets

	return &key, nil
}

// Materialize returns the octets for this symmetric key.
// Since this is a symmetric key, this just calls Octets
func (s SymmetricKey) Materialize(v interface{}) error {
	return assignMaterializeResult(v, s.octets)
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (s SymmetricKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var octets []byte
	if err := s.Materialize(&octets); err != nil {
		return nil, errors.Wrap(err, `failed to materialize symmetric key`)
	}

	h := hash.New()
	fmt.Fprint(h, `{"k":"`)
	fmt.Fprint(h, base64.EncodeToString(octets))
	fmt.Fprint(h, `","kty":"oct"}`)
	return h.Sum(nil), nil
}
