package jwk

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

// Mental note:
//
// Curve25519 refers to a particular curve, and is represented in its Montgomery form.
//
// Ed25519 refers to the biratinally equivalent curve of Curve25519, except it's in Edwards form.
// Ed25519 is the name of the curve and the also the signature scheme using that curve.
// The full name of the scheme is Edwards Curve Digital Signature Algorithm, and thus it is
// also referred to as EdDSA.
//
// X25519 refers to the Diffie-Hellman key exchange protocol that uses Cruve25519.
// Because this is an elliptic curve based Diffie Hellman protocol, it is also referred to
// as ECDH.
//
// OKP keys are used to represent private/public pairs of thse elliptic curve
// keys. But note that the name just means Octet Key Pair.

func (k *okpPublicKey) FromRaw(rawKeyIf interface{}) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	var crv jwa.EllipticCurveAlgorithm
	switch rawKey := rawKeyIf.(type) {
	case ed25519.PublicKey:
		k.x = rawKey
		crv = jwa.Ed25519
		k.crv = &crv
	case *ecdh.PublicKey:
		k.x = rawKey.Bytes()
		crv = jwa.X25519
		k.crv = &crv
	default:
		return fmt.Errorf(`unknown key type %T`, rawKeyIf)
	}

	return nil
}

func (k *okpPrivateKey) FromRaw(rawKeyIf interface{}) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	var crv jwa.EllipticCurveAlgorithm
	switch rawKey := rawKeyIf.(type) {
	case ed25519.PrivateKey:
		k.d = rawKey.Seed()
		k.x = rawKey.Public().(ed25519.PublicKey) //nolint:forcetypeassert
		crv = jwa.Ed25519
		k.crv = &crv
	case *ecdh.PrivateKey:
		// k.d = rawKey.Seed()
		k.d = rawKey.Bytes()
		k.x = rawKey.Public().(*ecdh.PublicKey).Bytes() //nolint:forcetypeassert
		crv = jwa.X25519
		k.crv = &crv
	default:
		return fmt.Errorf(`unknown key type %T`, rawKeyIf)
	}

	return nil
}

func buildOKPPublicKey(alg jwa.EllipticCurveAlgorithm, xbuf []byte) (interface{}, error) {
	switch alg {
	case jwa.Ed25519:
		return ed25519.PublicKey(xbuf), nil
	case jwa.X25519:
		ret, err := ecdh.X25519().NewPublicKey(xbuf)
		if err != nil {
			return nil, fmt.Errorf(`failed to parse x25519 public key: %w`, err)
		}
		return ret, nil
	default:
		return nil, fmt.Errorf(`invalid curve algorithm %s`, alg)
	}
}

// Raw returns the EC-DSA public key represented by this JWK
func (k *okpPublicKey) Raw(v interface{}) error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	pubk, err := buildOKPPublicKey(k.Crv(), k.x)
	if err != nil {
		return fmt.Errorf(`jwk.OKPPublicKey: failed to build public key: %w`, err)
	}

	if err := blackmagic.AssignIfCompatible(v, pubk); err != nil {
		return fmt.Errorf(`jwk.OKPPublicKey: failed to assign to destination variable: %w`, err)
	}
	return nil
}

func buildOKPPrivateKey(alg jwa.EllipticCurveAlgorithm, xbuf []byte, dbuf []byte) (interface{}, error) {
	if len(dbuf) == 0 {
		return nil, fmt.Errorf(`cannot use empty seed`)
	}
	switch alg {
	case jwa.Ed25519:
		if len(dbuf) != ed25519.SeedSize {
			return nil, fmt.Errorf(`wrong private key size`)
		}
		ret := ed25519.NewKeyFromSeed(dbuf)
		//nolint:forcetypeassert
		if !bytes.Equal(xbuf, ret.Public().(ed25519.PublicKey)) {
			return nil, fmt.Errorf(`invalid x value given d value`)
		}
		return ret, nil
	case jwa.X25519:
		ret, err := ecdh.X25519().NewPrivateKey(dbuf)
		if err != nil {
			return nil, fmt.Errorf(`unable to construct x25519 private key from seed: %w`, err)
		}
		//nolint:forcetypeassert
		if !bytes.Equal(xbuf, ret.Public().(*ecdh.PublicKey).Bytes()) {
			return nil, fmt.Errorf(`invalid x value given d value`)
		}
		return ret, nil
	default:
		return nil, fmt.Errorf(`invalid curve algorithm %s`, alg)
	}
}

func (k *okpPrivateKey) Raw(v interface{}) error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	privk, err := buildOKPPrivateKey(k.Crv(), k.x, k.d)
	if err != nil {
		return fmt.Errorf(`jwk.OKPPrivateKey: failed to build public key: %w`, err)
	}

	if err := blackmagic.AssignIfCompatible(v, privk); err != nil {
		return fmt.Errorf(`jwk.OKPPrivateKey: failed to assign to destination variable: %w`, err)
	}
	return nil
}

func makeOKPPublicKey(v interface {
	makePairs() []*HeaderPair
}) (Key, error) {
	newKey := newOKPPublicKey()

	// Iterate and copy everything except for the bits that should not be in the public key
	for _, pair := range v.makePairs() {
		switch pair.Key {
		case OKPDKey:
			continue
		default:
			//nolint:forcetypeassert
			key := pair.Key.(string)
			if err := newKey.Set(key, pair.Value); err != nil {
				return nil, fmt.Errorf(`failed to set field %q: %w`, key, err)
			}
		}
	}

	return newKey, nil
}

func (k *okpPrivateKey) PublicKey() (Key, error) {
	return makeOKPPublicKey(k)
}

func (k *okpPublicKey) PublicKey() (Key, error) {
	return makeOKPPublicKey(k)
}

func okpThumbprint(hash crypto.Hash, crv, x string) []byte {
	h := hash.New()
	fmt.Fprint(h, `{"crv":"`)
	fmt.Fprint(h, crv)
	fmt.Fprint(h, `","kty":"OKP","x":"`)
	fmt.Fprint(h, x)
	fmt.Fprint(h, `"}`)
	return h.Sum(nil)
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638 / 8037
func (k okpPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return okpThumbprint(
		hash,
		k.Crv().String(),
		base64.EncodeToString(k.x),
	), nil
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638 / 8037
func (k okpPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return okpThumbprint(
		hash,
		k.Crv().String(),
		base64.EncodeToString(k.x),
	), nil
}
