package jwk

import (
	"crypto"
	"fmt"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/pkg/errors"
)

func NewSymmetricKey() SymmetricKey {
	return newSymmetricKey()
}

func newSymmetricKey() *symmetricKey {
	return &symmetricKey{
		privateParams: make(map[string]interface{}),
	}
}

func (k *symmetricKey) FromRaw(v interface{}) error {
	octets, ok := v.([]byte)
	if !ok {
		return errors.Errorf(`(jwk.SymmetricKey).FromRaw requires []byte as the argument (%T)`, v)
	}

	if len(octets) == 0 {
		return errors.New(`non-empty []byte key required`)
	}

	k.octets = octets

	return nil
}

// Materialize returns the octets for this symmetric key.
// Since this is a symmetric key, this just calls Octets
func (k symmetricKey) Materialize(v interface{}) error {
	return assignMaterializeResult(v, k.octets)
}

// Thumbprint returns the JWK thumbprint using the indicated
// hakhing algorithm, according to RFC 7638
func (k symmetricKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var octets []byte
	if err := k.Materialize(&octets); err != nil {
		return nil, errors.Wrap(err, `failed to materialize symmetric key`)
	}

	h := hash.New()
	fmt.Fprint(h, `{"k":"`)
	fmt.Fprint(h, base64.EncodeToString(octets))
	fmt.Fprint(h, `","kty":"oct"}`)
	return h.Sum(nil), nil
}
