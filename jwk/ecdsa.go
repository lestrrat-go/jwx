package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/lestrrat/go-jwx/jwa"
)

func NewEcdsaPublicKey(pk *ecdsa.PublicKey) *EcdsaPublicKey {
	pubkey := &EcdsaPublicKey{
		Curve: jwa.EllipticCurveAlgorithm(pk.Params().Name),
	}
	pubkey.X.SetBytes(pk.X.Bytes())
	pubkey.Y.SetBytes(pk.Y.Bytes())
	return pubkey
}

func NewEcdsaPrivateKey(pk *ecdsa.PrivateKey) *EcdsaPrivateKey {
	pubkey := NewEcdsaPublicKey(&pk.PublicKey)
	privkey := &EcdsaPrivateKey{EcdsaPublicKey: pubkey}
	privkey.D.SetBytes(pk.D.Bytes())
	return privkey
}

func (k *EcdsaPublicKey) PublicKey() (*ecdsa.PublicKey, error) {
	var crv elliptic.Curve
	switch k.Curve {
	case jwa.P256:
		crv = elliptic.P256()
	case jwa.P384:
		crv = elliptic.P384()
	case jwa.P521:
		crv = elliptic.P521()
	default:
		return nil, ErrUnsupportedCurve
	}

	pubkey := &ecdsa.PublicKey{
		Curve: crv,
		X:     (&big.Int{}).SetBytes(k.X.Bytes()),
		Y:     (&big.Int{}).SetBytes(k.Y.Bytes()),
	}
	return pubkey, nil
}

func (k *EcdsaPrivateKey) PrivateKEy() (*ecdsa.PrivateKey, error) {
	pubkey, err := k.EcdsaPublicKey.PublicKey()
	if err != nil {
		return nil, err
	}

	privkey := &ecdsa.PrivateKey{
		PublicKey: *pubkey,
		D:         (&big.Int{}).SetBytes(k.D.Bytes()),
	}
	return privkey, nil
}
