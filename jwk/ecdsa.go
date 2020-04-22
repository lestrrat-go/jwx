package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

func newECDSAPublicKey(rawKey *ecdsa.PublicKey) (*ECDSAPublicKey, error) {
	var key ECDSAPublicKey
	key.privateParams = make(map[string]interface{})
	key.Set(KeyTypeKey, jwa.EC)
	key.x = rawKey.X.Bytes()
	key.y = rawKey.Y.Bytes()
	switch rawKey.Curve {
	case elliptic.P256():
		key.Set(ecdsaCrvKey, jwa.P256)
	case elliptic.P384():
		key.Set(ecdsaCrvKey, jwa.P384)
	case elliptic.P521():
		key.Set(ecdsaCrvKey, jwa.P521)
	default:
		return nil, errors.Errorf(`invalid elliptic curve %s`, rawKey.Curve)
	}

	return &key, nil
}

func newECDSAPrivateKey(rawKey *ecdsa.PrivateKey) (*ECDSAPrivateKey, error) {
	var key ECDSAPrivateKey
	key.privateParams = make(map[string]interface{})
	key.Set(KeyTypeKey, jwa.EC)
	key.x = rawKey.X.Bytes()
	key.y = rawKey.Y.Bytes()
	switch rawKey.Curve {
	case elliptic.P256():
		key.Set(ecdsaCrvKey, jwa.P256)
	case elliptic.P384():
		key.Set(ecdsaCrvKey, jwa.P384)
	case elliptic.P521():
		key.Set(ecdsaCrvKey, jwa.P521)
	default:
		return nil, errors.Errorf(`invalid elliptic curve %s`, rawKey.Curve)
	}

	key.d = rawKey.D.Bytes()

	return &key, nil
}

func ecdsaCurve(h Headers) jwa.EllipticCurveAlgorithm {
	if crv, ok := h.Get(ecdsaCrvKey); ok {
		return crv.(jwa.EllipticCurveAlgorithm)
	}
	return jwa.InvalidEllipticCurve
}

func (k *ECDSAPublicKey) Curve() jwa.EllipticCurveAlgorithm {
	return ecdsaCurve(k)
}

func (k *ECDSAPrivateKey) Curve() jwa.EllipticCurveAlgorithm {
	return ecdsaCurve(k)
}

func buildECDSAPublicKey(alg jwa.EllipticCurveAlgorithm, xbuf, ybuf []byte) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch alg {
	case jwa.P256:
		curve = elliptic.P256()
	case jwa.P384:
		curve = elliptic.P384()
	case jwa.P521:
		curve = elliptic.P521()
	default:
		return nil, errors.Errorf(`invalid curve algorithm %s`, alg)
	}

	var x, y big.Int
	x.SetBytes(xbuf)
	y.SetBytes(ybuf)

	return &ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}, nil
}

// Materialize returns the EC-DSA public key represented by this JWK
func (k *ECDSAPublicKey) Materialize(v interface{}) error {
	pubk, err := buildECDSAPublicKey(k.Curve(), k.x, k.y)
	if err != nil {
		return errors.Wrap(err, `failed to build public key`)
	}

	return assignMaterializeResult(v, pubk)
}

func (k *ECDSAPrivateKey) Materialize(v interface{}) error {
	pubk, err := buildECDSAPublicKey(k.Curve(), k.x, k.y)
	if err != nil {
		return errors.Wrap(err, `failed to build public key`)
	}

	var key ecdsa.PrivateKey
	var d big.Int
	d.SetBytes(k.d)
	key.D = &d
	key.PublicKey = *pubk

	return assignMaterializeResult(v, &key)
}

func (k *ECDSAPrivateKey) PublicKey() (*ECDSAPublicKey, error) {
	var privk ecdsa.PrivateKey
	if err := k.Materialize(&privk); err != nil {
		return nil, errors.Wrap(err, `failed to materialize ECDSA private key`)
	}

	return newECDSAPublicKey(&privk.PublicKey)
}

func ecdsaThumbprint(hash crypto.Hash, crv, x, y string) []byte {
	h := hash.New()
	fmt.Fprint(h, `{"crv":"`)
	fmt.Fprint(h, crv)
	fmt.Fprint(h, `","kty":"EC","x":"`)
	fmt.Fprint(h, x)
	fmt.Fprint(h, `","y":"`)
	fmt.Fprint(h, y)
	fmt.Fprint(h, `"}`)
	return h.Sum(nil)
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k ECDSAPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var key ecdsa.PublicKey
	if err := k.Materialize(&key); err != nil {
		return nil, errors.Wrap(err, `failed to materialize ecdsa.PublicKey for thumbprint generation`)
	}
	return ecdsaThumbprint(
		hash,
		key.Curve.Params().Name,
		base64.EncodeToString(key.X.Bytes()),
		base64.EncodeToString(key.Y.Bytes()),
	), nil
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k ECDSAPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var key ecdsa.PrivateKey
	if err := k.Materialize(&key); err != nil {
		return nil, errors.Wrap(err, `failed to materialize ecdsa.PrivateKey for thumbprint generation`)
	}
	return ecdsaThumbprint(
		hash,
		key.Curve.Params().Name,
		base64.EncodeToString(key.X.Bytes()),
		base64.EncodeToString(key.Y.Bytes()),
	), nil
}

/*
const (
	ecdsaDKey   = `d`
	ecdsaXKey   = `x`
	ecdsaYKey   = `y`
	ecdsaCrvKey = `crv`
)
func populateECDSAHeaders(h Headers, key interface{}) {
	h.Set(KeyTypeKey, jwa.EC)

	var pubk *ecdsa.PublicKey
	if privk, ok := key.(*ecdsa.PrivateKey); ok {
		pubk = &privk.PublicKey
		h.Set(ecdsaDKey, privk.D.Bytes())
	}

	if pubk == nil {
		if v, ok := key.(*ecdsa.PublicKey); ok {
			pubk = v
		}
	}
	if pubk == nil {
		return
	}
	h.Set(ecdsaXKey, base64.EncodeToString(pubk.X.Bytes()))
	h.Set(ecdsaYKey, base64.EncodeToString(pubk.Y.Bytes()))
	h.Set(ecdsaCrvKey, pubk.Curve.Params().Name)
}

func newECDSAPublicKey(key *ecdsa.PublicKey) (*ECDSAPublicKey, error) {
	if key == nil {
		return nil, errors.New(`non-nil ecdsa.PublicKey required`)
	}

	hdr := NewHeaders()
	populateECDSAHeaders(hdr, key)
	return &ECDSAPublicKey{
		headers: hdr,
	}, nil
}

func newECDSAPrivateKey(key *ecdsa.PrivateKey) (*ECDSAPrivateKey, error) {
	if key == nil {
		return nil, errors.New(`non-nil ecdsa.PrivateKey required`)
	}

	hdr := NewHeaders()
	populateECDSAHeaders(hdr, key)
	return &ECDSAPrivateKey{
		headers: hdr,
	}, nil
}

func getECDSACurve(h Headers) jwa.EllipticCurveAlgorithm {
	crvname, err := getRequiredKey(h, ecdsaCrvKey)
	if err != nil {
		return jwa.PInvalid
	}

	var crv jwa.EllipticCurveAlgorithm
	if err := crv.Accept(string(crvname)); err != nil {
		return jwa.PInvalid
	}
	return crv
}

func (key *ECDSAPublicKey) Curve() jwa.EllipticCurveAlgorithm {
	return getECDSACurve(key.headers)
}

func (key *ECDSAPrivateKey) Curve() jwa.EllipticCurveAlgorithm {
	return getECDSACurve(key.headers)
}

/*
func (k ECDSAPublicKey) MarshalJSON() (buf []byte, err error) {
	return json.Marshal(k.headers)
}

func (k ECDSAPrivateKey) MarshalJSON() (buf []byte, err error) {
	return json.Marshal(k.headers)
}

func (k *ECDSAPublicKey) UnmarshalJSON(data []byte) (err error) {
	h := NewHeaders()
	if err := json.Unmarshal(data, &h); err != nil {
		return errors.Wrap(err, `failed to unmarshal public key`)
	}

	// Validate required fields
	if kty := h.KeyType(); kty != jwa.EC {
		return errors.Errorf(`failed to unmarshal ECDSA private key: kty field must be EC (%s)`, kty)
	}

	if _, ok := h.Get(ecdsaDKey); !ok {
		return errors.Errorf(`failed to unmarshal ECDSA private key: required field %s is not present`, ecdsaDKey)
	}

	k.headers = h
	return nil
}

func (k *ECDSAPrivateKey) UnmarshalJSON(data []byte) (err error) {
	h := NewHeaders()
	if err := json.Unmarshal(data, h); err != nil {
		return errors.Wrap(err, `failed to unmarshal public key`)
	}

	for iter := h.Iterate(context.TODO()); iter.Next(context.TODO()); {
		pair := iter.Pair()
		fmt.Printf("%s\n", pair.Key)
	}

	// Validate required fields
	if kty := h.KeyType(); kty != jwa.EC {
		return errors.Errorf(`failed to unmarshal ECDSA private key: kty field must be EC (%s)`, kty)
	}

	for _, name := range []string{ecdsaXKey, ecdsaYKey, ecdsaDKey, ecdsaCrvKey} {
		if _, ok := h.Get(name); !ok {
			return errors.Errorf(`failed to unmarshal ECDSA private key: required field %s is not present`, name)
		}
	}

	k.headers = h
	return nil
}

*/
