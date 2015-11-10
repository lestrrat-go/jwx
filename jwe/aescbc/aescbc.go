package aescbc

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"

	"github.com/lestrrat/go-jwx/internal/padbuf"
)

const NonceSize = 16

type AesCbcHmac struct {
	blockCipher  cipher.Block
	hash         func() hash.Hash
	keysize      int
	integrityKey []byte
}

type BlockCipherFunc func([]byte) (cipher.Block, error)

func New(key []byte, f BlockCipherFunc) (*AesCbcHmac, error) {
	keysize := len(key) / 2
	ikey := key[:keysize]
	ekey := key[keysize:]
	bc, err := f(ekey)
	if err != nil {
		return nil, err
	}

	var hfunc func() hash.Hash
	switch keysize {
	case 16:
		hfunc = sha256.New
	case 24:
		hfunc = sha512.New384
	case 32:
		hfunc = sha512.New
	default:
		return nil, errors.New("unsupported key size")
	}

	return &AesCbcHmac{
		blockCipher:  bc,
		hash:         hfunc,
		integrityKey: ikey,
		keysize:      keysize,
	}, nil
}

// NonceSize fulfills the crypto.AEAD interface
func (c AesCbcHmac) NonceSize() int {
	return NonceSize
}

// Overhead fulfills the crypto.AEAD interface
func (c AesCbcHmac) Overhead() int {
	return c.blockCipher.BlockSize() + c.keysize
}

func (c AesCbcHmac) ComputeAuthTag(aad, nonce, ciphertext []byte) []byte {
	buf := make([]byte, len(aad)+len(nonce)+len(ciphertext)+8)
	n := 0
	n += copy(buf, aad)
	n += copy(buf[n:], nonce)
	n += copy(buf[n:], ciphertext)
	binary.BigEndian.PutUint64(buf[n:], uint64(len(aad)*8))

	h := hmac.New(c.hash, c.integrityKey)
	h.Write(buf)
	s := h.Sum(nil)
	return s[:c.keysize]
}

func ensureSize(dst []byte, n int) []byte {
	// if the dst buffer has enough length just copy the relevant parts to it.
	// Otherwise create a new slice that's big enough, and operate on that
	// Note: I think go-jose has a bug in that it checks for cap(), but not len().
	ret := dst
	if diff := n - len(dst); diff > 0 {
		// dst is not big enough
		ret = make([]byte, n)
		copy(ret, dst)
	}
	return ret
}

// Seal fulfills the crypto.AEAD interface
func (c AesCbcHmac) Seal(dst, nonce, plaintext, data []byte) []byte {
	/* original code:
	// Output buffer -- must take care not to mangle plaintext input.
	ciphertext := make([]byte, len(plaintext)+c.Overhead())[:len(plaintext)]
	copy(ciphertext, plaintext)
	ciphertext = padBuffer(ciphertext, c.blockCipher.BlockSize())
	*/
	ctlen := len(plaintext)
	ciphertext := make([]byte, ctlen+c.Overhead())[:ctlen]
	copy(ciphertext, plaintext)
	ciphertext = padbuf.PadBuffer(ciphertext).Pad(c.blockCipher.BlockSize())

	cbc := cipher.NewCBCEncrypter(c.blockCipher, nonce)
	cbc.CryptBlocks(ciphertext, ciphertext)

	authtag := c.ComputeAuthTag(data, nonce, ciphertext)

	retlen := len(dst) + len(ciphertext) + len(authtag)

	ret := ensureSize(dst, retlen)
	out := ret[len(dst):]
	n := copy(out, ciphertext)
	n += copy(out[n:], authtag)

	return ret
}

// Open fulfills the crypto.AEAD interface
func (c AesCbcHmac) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(ciphertext) < c.keysize {
		return nil, errors.New("invalid ciphertext (too short)")
	}

	tagOffset := len(ciphertext) - c.keysize
	if tagOffset%c.blockCipher.BlockSize() != 0 {
		return nil, errors.New("invalid ciphertext (invalid length)")
	}

	expectedTag := c.ComputeAuthTag(data, nonce, ciphertext[:tagOffset])
	if subtle.ConstantTimeCompare(expectedTag, ciphertext[tagOffset:]) != 1 {
		return nil, errors.New("invalid ciphertext (tag mismatch)")
	}

	cbc := cipher.NewCBCDecrypter(c.blockCipher, nonce)
	buf := make([]byte, tagOffset)
	cbc.CryptBlocks(buf, ciphertext[:tagOffset])

	plaintext, err := padbuf.PadBuffer(buf).Unpad(c.blockCipher.BlockSize())
	if err != nil {
		return nil, err
	}
	ret := ensureSize(dst, len(plaintext))
	out := ret[len(dst):]
	copy(out, plaintext)
	return ret, nil
}