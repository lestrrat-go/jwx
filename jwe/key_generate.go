package jwe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/lestrrat/go-jwx/internal/concatkdf"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/pkg/errors"
)

// Bytes returns the byte from this ByteKey
func (k ByteKey) Bytes() []byte {
	return []byte(k)
}

// KeySize returns the size of the key
func (g StaticKeyGenerate) KeySize() int {
	return len(g)
}

// KeyGenerate returns the key
func (g StaticKeyGenerate) KeyGenerate() (ByteSource, error) {
	buf := make([]byte, g.KeySize())
	copy(buf, g)
	return ByteKey(buf), nil
}

// NewRandomKeyGenerate creates a new KeyGenerator that returns
// randome bytes
func NewRandomKeyGenerate(n int) RandomKeyGenerate {
	return RandomKeyGenerate{keysize: n}
}

// KeySize returns the key size
func (g RandomKeyGenerate) KeySize() int {
	return g.keysize
}

// KeyGenerate generates a random new key
func (g RandomKeyGenerate) KeyGenerate() (ByteSource, error) {
	buf := make([]byte, g.keysize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, errors.Wrap(err, "failed to read from rand.Reader")
	}
	return ByteKey(buf), nil
}

// NewEcdhesKeyGenerate creates a new key generator using ECDH-ES
func NewEcdhesKeyGenerate(alg jwa.KeyEncryptionAlgorithm, pubkey *ecdsa.PublicKey) (*EcdhesKeyGenerate, error) {
	var keysize int
	switch alg {
	case jwa.ECDH_ES:
		return nil, errors.New("unimplemented")
	case jwa.ECDH_ES_A128KW:
		keysize = 16
	case jwa.ECDH_ES_A192KW:
		keysize = 24
	case jwa.ECDH_ES_A256KW:
		keysize = 32
	default:
		return nil, errors.Wrap(ErrUnsupportedAlgorithm, "invalid ECDH-ES key generation algorithm")
	}

	return &EcdhesKeyGenerate{
		algorithm: alg,
		keysize:   keysize,
		pubkey:    pubkey,
	}, nil
}

// KeySize returns the key size associated with this generator
func (g EcdhesKeyGenerate) KeySize() int {
	return g.keysize
}

// KeyGenerate generates new keys using ECDH-ES
func (g EcdhesKeyGenerate) KeyGenerate() (ByteSource, error) {
	priv, err := ecdsa.GenerateKey(g.pubkey.Curve, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key for ECDH-ES")
	}

	pubinfo := make([]byte, 4)
	binary.BigEndian.PutUint32(pubinfo, uint32(g.keysize)*8)

	z, _ := priv.PublicKey.Curve.ScalarMult(g.pubkey.X, g.pubkey.Y, priv.D.Bytes())
	kdf := concatkdf.New(crypto.SHA256, []byte(g.algorithm.String()), z.Bytes(), []byte{}, []byte{}, pubinfo, []byte{})
	kek := make([]byte, g.keysize)
	kdf.Read(kek)

	return ByteWithECPrivateKey{
		PrivateKey: priv,
		ByteKey:    ByteKey(kek),
	}, nil
}

// HeaderPopulate populates the header with the required EC-DSA public key
// infromation ('epk' key)
func (k ByteWithECPrivateKey) HeaderPopulate(h *Header) {
	h.Set("epk", jwk.NewEcdsaPublicKey(&k.PrivateKey.PublicKey))
}
