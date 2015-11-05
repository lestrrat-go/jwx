package jwk

import (
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/lestrrat/go-jwx/buffer"
)

func NewRsaPublicKey(pk *rsa.PublicKey) (*RsaPublicKey, error) {
	k := &RsaPublicKey{
		Essential: &Essential{KeyType: "RSA"},
		N:         buffer.Buffer(pk.N.Bytes()),
		E:         buffer.FromUint(uint64(pk.E)),
	}
	return k, nil
}

func NewRsaPrivateKey(pk *rsa.PrivateKey) (*RsaPrivateKey, error) {
	if len(pk.Primes) < 2 {
		return nil, errors.New("two primes required for RSA private key")
	}

	pub, err := NewRsaPublicKey(&pk.PublicKey)
	if err != nil {
		return nil, err
	}

	k := &RsaPrivateKey{
		RsaPublicKey: pub,
		D:            buffer.Buffer(pk.D.Bytes()),
		P:            buffer.Buffer(pk.Primes[0].Bytes()),
		Q:            buffer.Buffer(pk.Primes[1].Bytes()),
	}

	return k, nil
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
