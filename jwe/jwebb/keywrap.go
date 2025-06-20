package jwebb

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/pool"
)

var keywrapDefaultIV = []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

const keywrapChunkLen = 8

func Wrap(kek cipher.Block, cek []byte) ([]byte, error) {
	if len(cek)%8 != 0 {
		return nil, fmt.Errorf(`keywrap input must be 8 byte blocks`)
	}

	n := len(cek) / keywrapChunkLen
	r := make([][]byte, n)

	for i := range n {
		r[i] = make([]byte, keywrapChunkLen)
		copy(r[i], cek[i*keywrapChunkLen:])
	}

	buffer := pool.ByteSlice().GetCapacity(keywrapChunkLen * 2)
	defer pool.ByteSlice().Put(buffer)
	// the byte slice has the capacity, but len is 0
	buffer = buffer[:keywrapChunkLen*2]

	tBytes := pool.ByteSlice().GetCapacity(keywrapChunkLen)
	defer pool.ByteSlice().Put(tBytes)
	// the byte slice has the capacity, but len is 0
	tBytes = tBytes[:keywrapChunkLen]

	copy(buffer, keywrapDefaultIV)

	for t := range 6 * n {
		copy(buffer[keywrapChunkLen:], r[t%n])

		kek.Encrypt(buffer, buffer)

		binary.BigEndian.PutUint64(tBytes, uint64(t+1))

		for i := range keywrapChunkLen {
			buffer[i] = buffer[i] ^ tBytes[i]
		}
		copy(r[t%n], buffer[keywrapChunkLen:])
	}

	out := make([]byte, (n+1)*keywrapChunkLen)
	copy(out, buffer[:keywrapChunkLen])
	for i := range r {
		copy(out[(i+1)*8:], r[i])
	}

	return out, nil
}

func Unwrap(block cipher.Block, ciphertxt []byte) ([]byte, error) {
	if len(ciphertxt)%keywrapChunkLen != 0 {
		return nil, fmt.Errorf(`keyunwrap input must be %d byte blocks`, keywrapChunkLen)
	}

	n := (len(ciphertxt) / keywrapChunkLen) - 1
	r := make([][]byte, n)

	for i := range r {
		r[i] = make([]byte, keywrapChunkLen)
		copy(r[i], ciphertxt[(i+1)*keywrapChunkLen:])
	}

	buffer := pool.ByteSlice().GetCapacity(keywrapChunkLen * 2)
	defer pool.ByteSlice().Put(buffer)
	// the byte slice has the capacity, but len is 0
	buffer = buffer[:keywrapChunkLen*2]

	tBytes := pool.ByteSlice().GetCapacity(keywrapChunkLen)
	defer pool.ByteSlice().Put(tBytes)
	// the byte slice has the capacity, but len is 0
	tBytes = tBytes[:keywrapChunkLen]

	copy(buffer[:keywrapChunkLen], ciphertxt[:keywrapChunkLen])

	for t := 6*n - 1; t >= 0; t-- {
		binary.BigEndian.PutUint64(tBytes, uint64(t+1))

		for i := range keywrapChunkLen {
			buffer[i] = buffer[i] ^ tBytes[i]
		}
		copy(buffer[keywrapChunkLen:], r[t%n])

		block.Decrypt(buffer, buffer)

		copy(r[t%n], buffer[keywrapChunkLen:])
	}

	if subtle.ConstantTimeCompare(buffer[:keywrapChunkLen], keywrapDefaultIV) == 0 {
		return nil, fmt.Errorf(`key unwrap: failed to unwrap key`)
	}

	out := make([]byte, n*keywrapChunkLen)
	for i := range r {
		copy(out[i*keywrapChunkLen:], r[i])
	}

	return out, nil
}
