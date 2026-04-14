package jwebb

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
)

var keywrapDefaultIV = []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

func Wrap(kek cipher.Block, cek []byte) ([]byte, error) {
	if len(cek) < tokens.KeywrapChunkLen {
		return nil, fmt.Errorf(`keywrap input must be at least %d bytes`, tokens.KeywrapChunkLen)
	}
	if len(cek)%tokens.KeywrapBlockSize != 0 {
		return nil, fmt.Errorf(`keywrap input must be %d byte blocks`, tokens.KeywrapBlockSize)
	}

	n := len(cek) / tokens.KeywrapChunkLen

	// Single flat buffer for register values instead of [][]byte
	rBuf := make([]byte, n*tokens.KeywrapChunkLen)
	copy(rBuf, cek)

	buffer := pool.ByteSlice().GetCapacity(tokens.KeywrapChunkLen * 2)[:tokens.KeywrapChunkLen*2]
	defer pool.ByteSlice().Put(buffer)

	tBytes := pool.ByteSlice().GetCapacity(tokens.KeywrapChunkLen)[:tokens.KeywrapChunkLen]
	defer pool.ByteSlice().Put(tBytes)

	copy(buffer, keywrapDefaultIV)

	for t := range tokens.KeywrapRounds * n {
		idx := (t % n) * tokens.KeywrapChunkLen
		copy(buffer[tokens.KeywrapChunkLen:], rBuf[idx:idx+tokens.KeywrapChunkLen])

		kek.Encrypt(buffer, buffer)

		binary.BigEndian.PutUint64(tBytes, uint64(t+1))

		for i := range tokens.KeywrapChunkLen {
			buffer[i] = buffer[i] ^ tBytes[i]
		}
		copy(rBuf[idx:idx+tokens.KeywrapChunkLen], buffer[tokens.KeywrapChunkLen:])
	}

	out := make([]byte, (n+1)*tokens.KeywrapChunkLen)
	copy(out, buffer[:tokens.KeywrapChunkLen])
	copy(out[tokens.KeywrapChunkLen:], rBuf)

	return out, nil
}

func Unwrap(block cipher.Block, ciphertxt []byte) ([]byte, error) {
	if len(ciphertxt) < 2*tokens.KeywrapChunkLen {
		return nil, fmt.Errorf(`keyunwrap input must be at least %d bytes`, 2*tokens.KeywrapChunkLen)
	}
	if len(ciphertxt)%tokens.KeywrapChunkLen != 0 {
		return nil, fmt.Errorf(`keyunwrap input must be %d byte blocks`, tokens.KeywrapChunkLen)
	}

	n := (len(ciphertxt) / tokens.KeywrapChunkLen) - 1

	// Single flat buffer for register values instead of [][]byte
	rBuf := make([]byte, n*tokens.KeywrapChunkLen)
	copy(rBuf, ciphertxt[tokens.KeywrapChunkLen:])

	buffer := pool.ByteSlice().GetCapacity(tokens.KeywrapChunkLen * 2)[:tokens.KeywrapChunkLen*2]
	defer pool.ByteSlice().Put(buffer)

	tBytes := pool.ByteSlice().GetCapacity(tokens.KeywrapChunkLen)[:tokens.KeywrapChunkLen]
	defer pool.ByteSlice().Put(tBytes)

	copy(buffer[:tokens.KeywrapChunkLen], ciphertxt[:tokens.KeywrapChunkLen])

	for t := tokens.KeywrapRounds*n - 1; t >= 0; t-- {
		binary.BigEndian.PutUint64(tBytes, uint64(t+1))

		for i := range tokens.KeywrapChunkLen {
			buffer[i] = buffer[i] ^ tBytes[i]
		}
		idx := (t % n) * tokens.KeywrapChunkLen
		copy(buffer[tokens.KeywrapChunkLen:], rBuf[idx:idx+tokens.KeywrapChunkLen])

		block.Decrypt(buffer, buffer)

		copy(rBuf[idx:idx+tokens.KeywrapChunkLen], buffer[tokens.KeywrapChunkLen:])
	}

	if subtle.ConstantTimeCompare(buffer[:tokens.KeywrapChunkLen], keywrapDefaultIV) == 0 {
		return nil, fmt.Errorf(`key unwrap: failed to unwrap key`)
	}

	out := make([]byte, n*tokens.KeywrapChunkLen)
	copy(out, rBuf)

	return out, nil
}
