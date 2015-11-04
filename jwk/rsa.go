package jwk

import (
	"crypto/rsa"
	"errors"

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
