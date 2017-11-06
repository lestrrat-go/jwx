package jwk

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/pkg/errors"
)

// NewRsaPublicKey creates a new JWK using the given key
func NewRsaPublicKey(pk *rsa.PublicKey) (*RsaPublicKey, error) {
	k := &RsaPublicKey{
		EssentialHeader: &EssentialHeader{KeyType: "RSA"},
		N:               buffer.Buffer(pk.N.Bytes()),
		E:               buffer.FromUint(uint64(pk.E)),
	}
	return k, nil
}

// NewRsaPrivateKey creates a new JWK using the given key
func NewRsaPrivateKey(pk *rsa.PrivateKey) (*RsaPrivateKey, error) {
	if len(pk.Primes) < 2 {
		return nil, errors.New("two primes required for RSA private key")
	}

	pub, err := NewRsaPublicKey(&pk.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, `failed to construct jwk.RsaPrivateKey`)
	}

	k := &RsaPrivateKey{
		RsaPublicKey: pub,
		D:            buffer.Buffer(pk.D.Bytes()),
		P:            buffer.Buffer(pk.Primes[0].Bytes()),
		Q:            buffer.Buffer(pk.Primes[1].Bytes()),
	}

	return k, nil
}

// Materialize returns the RSA public key represented by this JWK
func (k *RsaPublicKey) Materialize() (interface{}, error) {
	return k.PublicKey()
}

// PublicKey creates a new rsa.PublicKey from the data given in the JWK
func (k *RsaPublicKey) PublicKey() (*rsa.PublicKey, error) {
	if k.N.Len() == 0 {
		return nil, errors.New("missing parameter 'N'")
	}
	if k.E.Len() == 0 {
		return nil, errors.New("missing parameter 'E'")
	}

	return &rsa.PublicKey{
		N: (&big.Int{}).SetBytes(k.N.Bytes()),
		E: int((&big.Int{}).SetBytes(k.E.Bytes()).Int64()),
	}, nil
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k RsaPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	const tmpl = `{"e":"%s","kty":"RSA","n":"%s"}`
	e64, err := k.E.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, `failed to base64 encode 'E' for jwk.RsaPublicKey`)
	}
	n64, err := k.N.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, `failed to base64 encode 'N' for jwk.RsaPublicKey`)
	}

	v := fmt.Sprintf(tmpl, e64, n64)
	h := hash.New()
	h.Write([]byte(v))
	return h.Sum(nil), nil
}

// Materialize returns the RSA private key represented by this JWK
func (k *RsaPrivateKey) Materialize() (interface{}, error) {
	return k.PrivateKey()
}

// PrivateKey creates a new rsa.PrivateKey from the data given in the JWK
func (k *RsaPrivateKey) PrivateKey() (*rsa.PrivateKey, error) {
	pubkey, err := k.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, `failed to get publick key`)
	}

	if k.D.Len() == 0 {
		return nil, errors.New("missing parameter 'D'")
	}
	if k.P.Len() == 0 {
		return nil, errors.New("missing parameter 'P'")
	}
	if k.Q.Len() == 0 {
		return nil, errors.New("missing parameter 'Q'")
	}

	privkey := &rsa.PrivateKey{
		PublicKey: *pubkey,
		D:         (&big.Int{}).SetBytes(k.D.Bytes()),
		Primes: []*big.Int{
			(&big.Int{}).SetBytes(k.P.Bytes()),
			(&big.Int{}).SetBytes(k.Q.Bytes()),
		},
	}

	if k.Dp.Len() > 0 {
		privkey.Precomputed.Dp = (&big.Int{}).SetBytes(k.Dp.Bytes())
	}
	if k.Dq.Len() > 0 {
		privkey.Precomputed.Dq = (&big.Int{}).SetBytes(k.Dq.Bytes())
	}
	if k.Qi.Len() > 0 {
		privkey.Precomputed.Qinv = (&big.Int{}).SetBytes(k.Qi.Bytes())
	}

	if err := privkey.Validate(); err != nil {
		return nil, errors.Wrap(err, `validation failed for private key`)
	}

	return privkey, nil
}
