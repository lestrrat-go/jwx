package keygen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/lestrrat-go/jwx/buffer"
	"github.com/lestrrat-go/jwx/internal/concatkdf"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

// Bytes returns the byte from this ByteKey
func (k ByteKey) Bytes() []byte {
	return []byte(k)
}

// Size returns the size of the key
func (g Static) Size() int {
	return len(g)
}

// Generate returns the key
func (g Static) Generate() (ByteSource, error) {
	buf := make([]byte, g.Size())
	copy(buf, g)
	return ByteKey(buf), nil
}

// NewRandom creates a new Generator that returns
// random bytes
func NewRandom(n int) Random {
	return Random{keysize: n}
}

// Size returns the key size
func (g Random) Size() int {
	return g.keysize
}

// Generate generates a random new key
func (g Random) Generate() (ByteSource, error) {
	buf := make([]byte, g.keysize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, errors.Wrap(err, "failed to read from rand.Reader")
	}
	return ByteKey(buf), nil
}

// NewEcdhes creates a new key generator using ECDH-ES
func NewEcdhes(alg jwa.KeyEncryptionAlgorithm, enc jwa.ContentEncryptionAlgorithm, keysize int, pubkey *ecdsa.PublicKey) (*Ecdhes, error) {
	return &Ecdhes{
		algorithm: alg,
		enc:       enc,
		keysize:   keysize,
		pubkey:    pubkey,
	}, nil
}

// Size returns the key size associated with this generator
func (g Ecdhes) Size() int {
	return g.keysize
}

// Generate generates new keys using ECDH-ES
func (g Ecdhes) Generate() (ByteSource, error) {
	priv, err := ecdsa.GenerateKey(g.pubkey.Curve, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key for ECDH-ES")
	}

	var algorithm string
	if g.algorithm == jwa.ECDH_ES {
		algorithm = g.enc.String()
	} else {
		algorithm = g.algorithm.String()
	}

	pubinfo := make([]byte, 4)
	binary.BigEndian.PutUint32(pubinfo, uint32(g.keysize)*8)

	z, _ := priv.PublicKey.Curve.ScalarMult(g.pubkey.X, g.pubkey.Y, priv.D.Bytes())
	kdf := concatkdf.New(crypto.SHA256, []byte(algorithm), z.Bytes(), []byte{}, []byte{}, pubinfo, []byte{})
	kek := make([]byte, g.keysize)
	if _, err := kdf.Read(kek); err != nil {
		return nil, errors.Wrap(err, "failed to read kdf")
	}

	return ByteWithECPrivateKey{
		PrivateKey: priv,
		ByteKey:    ByteKey(kek),
	}, nil
}

// HeaderPopulate populates the header with the required EC-DSA public key
// information ('epk' key)
func (k ByteWithECPrivateKey) Populate(h Setter) error {
	key, err := jwk.New(&k.PrivateKey.PublicKey)
	if err != nil {
		return errors.Wrap(err, "failed to create JWK")
	}

	if err := h.Set("epk", key); err != nil {
		return errors.Wrap(err, "failed to write header")
	}
	return nil
}

// HeaderPopulate populkates the header with the required AES GCM
// parameters ('iv' and 'tag')
func (k ByteWithIVAndTag) Populate(h Setter) error {
	if err := h.Set("iv", buffer.Buffer(k.IV)); err != nil {
		return errors.Wrap(err, "failed to write header")
	}

	if err := h.Set("tag", buffer.Buffer(k.Tag)); err != nil {
		return errors.Wrap(err, "failed to write header")
	}

	return nil
}

// HeaderPopulate populkates the header with the required PBES2
// parameters ('p2s' and 'p2c')
func (k ByteWithSaltAndCount) Populate(h Setter) error {
	if err := h.Set("p2c", k.Count); err != nil {
		return errors.Wrap(err, "failed to write header")
	}

	if err := h.Set("p2s", buffer.Buffer(k.Salt)); err != nil {
		return errors.Wrap(err, "failed to write header")
	}

	return nil
}
