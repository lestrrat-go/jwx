package jwk

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"fmt"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/byteslice"
	"github.com/lestrrat-go/jwx/v2/internal/base64"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/x25519"
)

var _ OKPPrivateKey = &okpPrivateKey{}
var _ OKPPublicKey = &okpPublicKey{}

func (k *okpPublicKey) FromRaw(rawKeyIf interface{}) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	var crv jwa.EllipticCurveAlgorithm
	switch rawKey := rawKeyIf.(type) {
	case ed25519.PublicKey:
		xbuf := []byte(rawKey)
		if k.x == nil {
			k.x = byteslice.New(xbuf)
		} else {
			k.x.SetBytes(xbuf)
		}
		crv = jwa.Ed25519
		k.crv = &crv
	case x25519.PublicKey:
		xbuf := []byte(rawKey)
		if k.x == nil {
			k.x = byteslice.New(xbuf)
		} else {
			k.x.SetBytes(xbuf)
		}

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
		dbuf := rawKey.Seed()
		if k.d == nil {
			k.d = byteslice.New(dbuf)
		} else {
			k.d.SetBytes(dbuf)
		}

		xbuf := []byte(rawKey.Public().(ed25519.PublicKey)) //nolint:forcetypeassert
		if k.x == nil {
			k.x = byteslice.New(xbuf)
		} else {
			k.x.SetBytes(xbuf)
		}
		crv = jwa.Ed25519
		k.crv = &crv
	case x25519.PrivateKey:
		dbuf := rawKey.Seed()
		if k.d == nil {
			k.d = byteslice.New(dbuf)
		} else {
			k.d.SetBytes(dbuf)
		}

		xbuf := []byte(rawKey.Public().(x25519.PublicKey)) //nolint:forcetypeassert
		if k.x == nil {
			k.x = byteslice.New(xbuf)
		} else {
			k.x.SetBytes(xbuf)
		}
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
		return x25519.PublicKey(xbuf), nil
	default:
		return nil, fmt.Errorf(`invalid curve algorithm %s`, alg)
	}
}

// Raw returns the EC-DSA public key represented by this JWK
func (k *okpPublicKey) Raw(v interface{}) error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	pubk, err := buildOKPPublicKey(k.Crv(), k.x.Bytes())
	if err != nil {
		return fmt.Errorf(`failed to build public key: %w`, err)
	}

	return blackmagic.AssignIfCompatible(v, pubk)
}

func buildOKPPrivateKey(alg jwa.EllipticCurveAlgorithm, xbuf []byte, dbuf []byte) (interface{}, error) {
	switch alg {
	case jwa.Ed25519:
		ret := ed25519.NewKeyFromSeed(dbuf)
		//nolint:forcetypeassert
		if !bytes.Equal(xbuf, ret.Public().(ed25519.PublicKey)) {
			return nil, fmt.Errorf(`invalid x value given d value`)
		}
		return ret, nil
	case jwa.X25519:
		ret, err := x25519.NewKeyFromSeed(dbuf)
		if err != nil {
			return nil, fmt.Errorf(`unable to construct x25519 private key from seed: %w`, err)
		}
		//nolint:forcetypeassert
		if !bytes.Equal(xbuf, ret.Public().(x25519.PublicKey)) {
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

	privk, err := buildOKPPrivateKey(k.Crv(), k.x.Bytes(), k.d.Bytes())
	if err != nil {
		return fmt.Errorf(`failed to build public key: %w`, err)
	}

	return blackmagic.AssignIfCompatible(v, privk)
}

func makeOKPPublicKey(v iteratable) (Key, error) {
	newKey := newOKPPublicKey()

	// Iterate and copy everything except for the bits that should not be in the public key
	for _, key := range v.FieldNames() {
		switch key {
		case OKPDKey:
			continue
		default:
			var val interface{}
			if err := v.Get(key, &val); err != nil {
				return nil, fmt.Errorf(`failed to retrieve value for field %q: %w`, key, err)
			}

			if err := newKey.Set(key, val); err != nil {
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
func (k *okpPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return okpThumbprint(
		hash,
		k.Crv().String(),
		base64.EncodeToString(k.x.Bytes()),
	), nil
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638 / 8037
func (k *okpPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return okpThumbprint(
		hash,
		k.Crv().String(),
		base64.EncodeToString(k.x.Bytes()),
	), nil
}
