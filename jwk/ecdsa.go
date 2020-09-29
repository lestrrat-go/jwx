package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"sync"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

func NewECDSAPublicKey() ECDSAPublicKey {
	return newECDSAPublicKey()
}

func newECDSAPublicKey() *ecdsaPublicKey {
	return &ecdsaPublicKey{
		privateParams: make(map[string]interface{}),
	}
}

func NewECDSAPrivateKey() ECDSAPrivateKey {
	return newECDSAPrivateKey()
}

func newECDSAPrivateKey() *ecdsaPrivateKey {
	return &ecdsaPrivateKey{
		privateParams: make(map[string]interface{}),
	}
}

func (k *ecdsaPublicKey) FromRaw(rawKey *ecdsa.PublicKey) error {
	k.x = rawKey.X.Bytes()
	k.y = rawKey.Y.Bytes()
	switch rawKey.Curve {
	case elliptic.P256():
		if err := k.Set(ECDSACrvKey, jwa.P256); err != nil {
			return errors.Wrap(err, `failed to set header`)
		}
	case elliptic.P384():
		if err := k.Set(ECDSACrvKey, jwa.P384); err != nil {
			return errors.Wrap(err, `failed to set header`)
		}
	case elliptic.P521():
		if err := k.Set(ECDSACrvKey, jwa.P521); err != nil {
			return errors.Wrap(err, `failed to set header`)
		}
	default:
		return errors.Errorf(`invalid elliptic curve %s`, rawKey.Curve)
	}

	return nil
}

func (k *ecdsaPrivateKey) FromRaw(rawKey *ecdsa.PrivateKey) error {
	k.x = rawKey.X.Bytes()
	k.y = rawKey.Y.Bytes()
	switch rawKey.Curve {
	case elliptic.P256():
		if err := k.Set(ECDSACrvKey, jwa.P256); err != nil {
			return errors.Wrap(err, "failed to write header")
		}
	case elliptic.P384():
		if err := k.Set(ECDSACrvKey, jwa.P384); err != nil {
			return errors.Wrap(err, "failed to write header")
		}
	case elliptic.P521():
		if err := k.Set(ECDSACrvKey, jwa.P521); err != nil {
			return errors.Wrap(err, "failed to write header")
		}
	default:
		return errors.Errorf(`invalid elliptic curve %s`, rawKey.Curve)
	}

	k.d = rawKey.D.Bytes()

	return nil
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

// Raw returns the EC-DSA public key represented by this JWK
func (k *ecdsaPublicKey) Raw(v interface{}) error {
	pubk, err := buildECDSAPublicKey(k.Crv(), k.x, k.y)
	if err != nil {
		return errors.Wrap(err, `failed to build public key`)
	}

	return assignRawResult(v, pubk)
}

func (k *ecdsaPrivateKey) Raw(v interface{}) error {
	pubk, err := buildECDSAPublicKey(k.Crv(), k.x, k.y)
	if err != nil {
		return errors.Wrap(err, `failed to build public key`)
	}

	var key ecdsa.PrivateKey
	var d big.Int
	d.SetBytes(k.d)
	key.D = &d
	key.PublicKey = *pubk

	return assignRawResult(v, &key)
}

func (k *ecdsaPrivateKey) PublicKey() (ECDSAPublicKey, error) {
	var privk ecdsa.PrivateKey
	if err := k.Raw(&privk); err != nil {
		return nil, errors.Wrap(err, `failed to materialize ECDSA private key`)
	}

	newKey := NewECDSAPublicKey()
	if err := newKey.FromRaw(&privk.PublicKey); err != nil {
		return nil, errors.Wrap(err, `failed to initialize ECDSAPublicKey`)
	}
	return newKey, nil
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
func (k ecdsaPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var key ecdsa.PublicKey
	if err := k.Raw(&key); err != nil {
		return nil, errors.Wrap(err, `failed to materialize ecdsa.PublicKey for thumbprint generation`)
	}

	xbuf := crvPointToFixedBuffer(key.X, key.Curve)
	ybuf := crvPointToFixedBuffer(key.Y, key.Curve)
	defer releaseCrvFixedBuffer(xbuf)
	defer releaseCrvFixedBuffer(ybuf)

	return ecdsaThumbprint(
		hash,
		key.Curve.Params().Name,
		base64.EncodeToString(xbuf),
		base64.EncodeToString(ybuf),
	), nil
}

var crvFixedBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 66)
		return &buf
	},
}

func getCrvFixedBuffer(size int) []byte {
	buf := *(crvFixedBufferPool.Get().(*[]byte))
	if size > 66 && cap(buf) < size {
		buf = append(buf, make([]byte, size-cap(buf))...)
	}
	return buf[:size]
}

func releaseCrvFixedBuffer(buf []byte) {
	buf = buf[:cap(buf)]
	buf[0] = 0x0
	for i := 1; i < len(buf); i *= 2 {
		copy(buf[i:], buf[:i])
	}
	crvFixedBufferPool.Put(&buf)
}

func crvPointToFixedBuffer(v *big.Int, crv elliptic.Curve) []byte {

	// We need to create a buffer that fits the entire curve.
	// If the curve size is 66, that fits in 9 bytes. If the curve
	// size is 64, it fits in 8 bytes.
	bits := crv.Params().BitSize

	// For most common cases we know before hand what the byte length
	// is going to be. optimize
	var inBytes int
	switch bits {
	case 224, 256, 384: // TODO: use constant?
		inBytes = bits / 8
	case 521:
		inBytes = 66 // 65 + 1
	default:
		inBytes = bits / 8
		if (bits % 8) != 0 {
			inBytes++
		}
	}

	buf := getCrvFixedBuffer(inBytes)
	return bigIntFillBytes(v, buf)
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k ecdsaPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var key ecdsa.PrivateKey
	if err := k.Raw(&key); err != nil {
		return nil, errors.Wrap(err, `failed to materialize ecdsa.PrivateKey for thumbprint generation`)
	}

	xbuf := crvPointToFixedBuffer(key.X, key.Curve)
	ybuf := crvPointToFixedBuffer(key.Y, key.Curve)
	defer releaseCrvFixedBuffer(xbuf)
	defer releaseCrvFixedBuffer(ybuf)

	return ecdsaThumbprint(
		hash,
		key.Curve.Params().Name,
		base64.EncodeToString(xbuf),
		base64.EncodeToString(ybuf),
	), nil
}
