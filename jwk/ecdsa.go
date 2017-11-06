package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/pkg/errors"
)

// i2osp converts an integer to a fixed length octet string as per RFC 3447
// section 4.1 where v is the integer and n is the octet string length.
func i2osp(v *big.Int, n int) []byte {
	b := v.Bytes()
	if len(b) < n {
		t := make([]byte, n)
		copy(t[n-len(b):], b)
		return t
	}
	return b
}

// NewEcdsaPublicKey creates a new JWK from a EC-DSA public key
func NewEcdsaPublicKey(pk *ecdsa.PublicKey) *EcdsaPublicKey {
	pubkey := &EcdsaPublicKey{
		EssentialHeader: &EssentialHeader{KeyType: jwa.EC},
		Curve:           jwa.EllipticCurveAlgorithm(pk.Params().Name),
	}
	n := pk.Params().BitSize / 8
	pubkey.X.SetBytes(i2osp(pk.X, n))
	pubkey.Y.SetBytes(i2osp(pk.Y, n))
	return pubkey
}

// NewEcdsaPrivateKey creates a new JWK from a EC-DSA private key
func NewEcdsaPrivateKey(pk *ecdsa.PrivateKey) *EcdsaPrivateKey {
	pubkey := NewEcdsaPublicKey(&pk.PublicKey)
	privkey := &EcdsaPrivateKey{EcdsaPublicKey: pubkey}
	privkey.D.SetBytes(i2osp(pk.D, pk.Params().BitSize/8))
	return privkey
}

// Materialize returns the EC-DSA public key represented by this JWK
func (k *EcdsaPublicKey) Materialize() (interface{}, error) {
	return k.PublicKey()
}

// PublicKey returns the EC-DSA public key represented by this JWK
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

// Materialize returns the EC-DSA private key represented by this JWK
func (k *EcdsaPrivateKey) Materialize() (interface{}, error) {
	return k.PrivateKey()
}

// PrivateKey returns the EC-DSA private key represented by this JWK
func (k *EcdsaPrivateKey) PrivateKey() (*ecdsa.PrivateKey, error) {
	pubkey, err := k.EcdsaPublicKey.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, `failed to get public key from ecdsa private key`)
	}

	privkey := &ecdsa.PrivateKey{
		PublicKey: *pubkey,
		D:         (&big.Int{}).SetBytes(k.D.Bytes()),
	}
	return privkey, nil
}
