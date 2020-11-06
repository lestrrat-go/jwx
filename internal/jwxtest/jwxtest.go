package jwxtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

func GenerateRsaKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GenerateRsaJwk() (jwk.Key, error) {
	key, err := GenerateRsaKey()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate RSA private key`)
	}

	k, err := jwk.New(key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.RSAPrivateKey`)
	}

	return k, nil
}

func GenerateRsaPublicJwk() (jwk.Key, error) {
	key, err := GenerateRsaJwk()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.RSAPrivateKey`)
	}

	return key.(jwk.RSAPrivateKey).PublicKey()
}

func GenerateEcdsaKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

func GenerateEcdsaJwk() (jwk.Key, error) {
	key, err := GenerateEcdsaKey()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate ECDSA private key`)
	}

	k, err := jwk.New(key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.ECDSAPrivateKey`)
	}

	return k, nil
}

func GenerateEcdsaPublicJwk() (jwk.Key, error) {
	key, err := GenerateEcdsaJwk()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.ECDSAPrivateKey`)
	}

	return key.(jwk.ECDSAPrivateKey).PublicKey()
}

func GenerateSymmetricKey() []byte {
	sharedKey := make([]byte, 64)
	//nolint:errcheck
	rand.Read(sharedKey)
	return sharedKey
}

func GenerateSymmetricJwk() (jwk.Key, error) {
	key, err := jwk.New(GenerateSymmetricKey())
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.SymmetricKey`)
	}

	return key, nil
}
