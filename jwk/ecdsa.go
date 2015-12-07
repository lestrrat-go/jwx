package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
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

func (k *EcdsaPublicKey) Materialize() (interface{}, error) {
	return k.PublicKey()
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

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k EcdsaPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	const tmpl = `{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`

	csize := k.Curve.Size()

	// We need to truncate the buffer at curve size
	xbuf := k.X.Bytes()
	if len(xbuf) > csize {
		xbuf = xbuf[:csize]
	}
	ybuf := k.Y.Bytes()
	if len(ybuf) > csize {
		ybuf = ybuf[:csize]
	}
	enc := base64.RawURLEncoding
	x64 := make([]byte, enc.EncodedLen(len(xbuf)))
	enc.Encode(x64, xbuf)
	y64 := make([]byte, enc.EncodedLen(len(ybuf)))
	enc.Encode(y64, ybuf)

	v := fmt.Sprintf(tmpl, k.Curve.String(), x64, y64)
	h := hash.New()
	h.Write([]byte(v))
	return h.Sum(nil), nil
}

func (k *EcdsaPrivateKey) Materialize() (interface{}, error) {
	return k.PrivateKey()
}

func (k *EcdsaPrivateKey) PrivateKey() (*ecdsa.PrivateKey, error) {
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
