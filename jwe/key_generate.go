package jwe

import (
	"crypto/rand"
	"io"
)

func (g StaticKeyGenerate) KeySize() int {
	return len(g)
}

func (g StaticKeyGenerate) KeyGenerate() ([]byte, error) {
	buf := make([]byte, g.KeySize())
	copy(buf, g)
	return buf, nil
}

func NewRandomKeyGenerate(n int) RandomKeyGenerate {
	return RandomKeyGenerate{keysize: n}
}

func (g RandomKeyGenerate) KeySize() int {
	return g.keysize
}

func (g RandomKeyGenerate) KeyGenerate() ([]byte, error) {
	buf := make([]byte, g.keysize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
