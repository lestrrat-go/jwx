// Package keywrap implements the required KeyWrap/KeyUnwrap for JWE.
// The code is pretty much borrowed from go-jose
package keywrap

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

var defaultIV = []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

const chunklen = 8

var ErrInvalidBlockSize = errors.New("input must be 8 byte blocks")

func Wrap(kek cipher.Block, cek []byte) ([]byte, error) {
	if len(cek)%8 != 0 {
		return nil, ErrInvalidBlockSize
	}

	n := len(cek) / chunklen
	r := make([][]byte, n)

	for i := 0; i < n; i++ {
		r[i] = make([]byte, chunklen)
		copy(r[i], cek[i*chunklen:])
	}

	buffer := make([]byte, chunklen*2)
	tBytes := make([]byte, chunklen)
	copy(buffer, defaultIV)

	for t := 0; t < 6*n; t++ {
		copy(buffer[chunklen:], r[t%n])

		kek.Encrypt(buffer, buffer)

		binary.BigEndian.PutUint64(tBytes, uint64(t+1))

		for i := 0; i < chunklen; i++ {
			buffer[i] = buffer[i] ^ tBytes[i]
		}
		copy(r[t%n], buffer[chunklen:])
	}

	out := make([]byte, (n+1)*chunklen)
	copy(out, buffer[:chunklen])
	for i := range r {
		copy(out[(i+1)*8:], r[i])
	}

	return out, nil
}

func Unwrap(block cipher.Block, ciphertxt []byte) ([]byte, error) {
	if len(ciphertxt)%chunklen != 0 {
		return nil, ErrInvalidBlockSize
	}

	n := (len(ciphertxt) / chunklen) - 1
	r := make([][]byte, n)

	for i := range r {
		r[i] = make([]byte, chunklen)
		copy(r[i], ciphertxt[(i+1)*chunklen:])
	}

	buffer := make([]byte, chunklen*2)
	tBytes := make([]byte, chunklen)
	copy(buffer[:chunklen], ciphertxt[:chunklen])

	for t := 6*n - 1; t >= 0; t-- {
		binary.BigEndian.PutUint64(tBytes, uint64(t+1))

		for i := 0; i < chunklen; i++ {
			buffer[i] = buffer[i] ^ tBytes[i]
		}
		copy(buffer[chunklen:], r[t%n])

		block.Decrypt(buffer, buffer)

		copy(r[t%n], buffer[chunklen:])
	}

	if subtle.ConstantTimeCompare(buffer[:chunklen], defaultIV) == 0 {
		return nil, errors.New("failed to unwrap key")
	}

	out := make([]byte, n*chunklen)
	for i := range r {
		copy(out[i*chunklen:], r[i])
	}

	return out, nil
}