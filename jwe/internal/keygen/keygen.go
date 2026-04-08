package keygen

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// Bytes returns the byte from this ByteKey
func (k ByteKey) Bytes() []byte {
	return []byte(k)
}

func Random(n int) (ByteSource, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf(`failed to read from rand.Reader: %w`, err)
	}
	return ByteKey(buf), nil
}

// HeaderPopulate populates the header with the required EC-DSA public key
// information ('epk' key)
func (k ByteWithECPublicKey) Populate(h Setter) error {
	key, err := jwk.Import[jwk.Key](k.PublicKey)
	if err != nil {
		return fmt.Errorf(`failed to create JWK: %w`, err)
	}

	if err := h.Set("epk", key); err != nil {
		return fmt.Errorf(`failed to write header: %w`, err)
	}
	return nil
}

// HeaderPopulate populates the header with the required AES GCM
// parameters ('iv' and 'tag')
func (k ByteWithIVAndTag) Populate(h Setter) error {
	if err := h.Set("iv", k.IV); err != nil {
		return fmt.Errorf(`failed to write header: %w`, err)
	}

	if err := h.Set("tag", k.Tag); err != nil {
		return fmt.Errorf(`failed to write header: %w`, err)
	}

	return nil
}

// Populate populates the header with the KEM ciphertext ('ek')
func (k ByteWithEncapsulatedKey) Populate(h Setter) error {
	if err := h.Set("ek", k.Ciphertext); err != nil {
		return fmt.Errorf(`failed to write header: %w`, err)
	}
	return nil
}

// HeaderPopulate populates the header with the required PBES2
// parameters ('p2s' and 'p2c')
func (k ByteWithSaltAndCount) Populate(h Setter) error {
	if err := h.Set("p2c", k.Count); err != nil {
		return fmt.Errorf(`failed to write header: %w`, err)
	}

	if err := h.Set("p2s", k.Salt); err != nil {
		return fmt.Errorf(`failed to write header: %w`, err)
	}

	return nil
}
