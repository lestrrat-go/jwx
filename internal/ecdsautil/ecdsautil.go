package ecdsautil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"strconv"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/pkg/errors"
)

type curve struct {
	elliptic.Curve
}

type rawkey struct {
	Curve curve         `json:"crv"`
	D     buffer.Buffer `json:"d"`
	X     buffer.Buffer `json:"x"`
	Y     buffer.Buffer `json:"y"`
}

func (c curve) MarshalJSON() ([]byte, error) {
	p := c.Params()
	switch p.BitSize {
	case 256, 384, 521:
		v := "P-" + strconv.Itoa(p.BitSize)
		return json.Marshal(v)
	default:
		return nil, errors.New("Unsupported curve")
	}
}

func (c *curve) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return errors.Wrap(err, `failed to unmarshal ecdsa curve`)
	}

	switch name {
	case "P-256":
		*c = curve{elliptic.P256()}
	case "P-384":
		*c = curve{elliptic.P384()}
	case "P-521":
		*c = curve{elliptic.P521()}
	default:
		return errors.New("Unsupported curve")
	}
	return nil
}

func NewRawKeyFromPublicKey(pubkey *ecdsa.PublicKey) *rawkey {
	r := &rawkey{}
	r.Curve = curve{pubkey.Curve}
	r.X = buffer.Buffer(pubkey.X.Bytes())
	r.Y = buffer.Buffer(pubkey.Y.Bytes())
	return r
}

func NewRawKeyFromPrivateKey(privkey *ecdsa.PrivateKey) *rawkey {
	r := NewRawKeyFromPublicKey(&privkey.PublicKey)
	r.D = buffer.Buffer(privkey.D.Bytes())
	return r
}

func PublicKeyFromJSON(data []byte) (*ecdsa.PublicKey, error) {
	r := rawkey{}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, errors.Wrap(err, `failed to unmarshal ecdsa public key`)
	}

	return r.GeneratePublicKey()
}

func PrivateKeyFromJSON(data []byte) (*ecdsa.PrivateKey, error) {
	r := rawkey{}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, errors.Wrap(err, `failed to unmarshal ecdsa private key`)
	}

	return r.GeneratePrivateKey()
}

func (r rawkey) GeneratePublicKey() (*ecdsa.PublicKey, error) {
	return &ecdsa.PublicKey{
		Curve: r.Curve.Curve,
		X:     (&big.Int{}).SetBytes(r.X.Bytes()),
		Y:     (&big.Int{}).SetBytes(r.Y.Bytes()),
	}, nil
}

func (r rawkey) GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
	pubkey, err := r.GeneratePublicKey()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate public key`)
	}

	privkey := &ecdsa.PrivateKey{
		PublicKey: *pubkey,
		D:         (&big.Int{}).SetBytes(r.D.Bytes()),
	}

	return privkey, nil
}
