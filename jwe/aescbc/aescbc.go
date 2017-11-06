package aescbc

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/lestrrat/go-jwx/internal/debug"
	"github.com/lestrrat/go-jwx/internal/padbuf"
	"github.com/pkg/errors"
)

const (
	NonceSize = 16
)

type AesCbcHmac struct {
	blockCipher  cipher.Block
	hash         func() hash.Hash
	keysize      int
	tagsize      int
	integrityKey []byte
}

type BlockCipherFunc func([]byte) (cipher.Block, error)

func New(key []byte, f BlockCipherFunc) (*AesCbcHmac, error) {
	keysize := len(key) / 2
	ikey := key[:keysize]
	ekey := key[keysize:]

	if debug.Enabled {
		debug.Printf("New: keysize               = %d", keysize)
		debug.Printf("New: cek (key)             = %x (%d)\n", key, len(key))
		debug.Printf("New: ikey                  = %x (%d)\n", ikey, len(ikey))
		debug.Printf("New: ekey                  = %x (%d)\n", ekey, len(ekey))
	}

	bc, err := f(ekey)
	if err != nil {
		return nil, errors.Wrap(err, `failed to execute block cipher function`)
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
		return nil, errors.Errorf("unsupported key size %d", keysize)
	}

	return &AesCbcHmac{
		blockCipher:  bc,
		hash:         hfunc,
		integrityKey: ikey,
		keysize:      keysize,
		tagsize:      NonceSize,
	}, nil
}

// NonceSize fulfills the crypto.AEAD interface
func (c AesCbcHmac) NonceSize() int {
	return NonceSize
}

// Overhead fulfills the crypto.AEAD interface
func (c AesCbcHmac) Overhead() int {
	return c.blockCipher.BlockSize() + c.tagsize
}

func (c AesCbcHmac) ComputeAuthTag(aad, nonce, ciphertext []byte) []byte {
	if debug.Enabled {
		debug.Printf("ComputeAuthTag: aad        = %x (%d)\n", aad, len(aad))
		debug.Printf("ComputeAuthTag: ciphertext = %x (%d)\n", ciphertext, len(ciphertext))
		debug.Printf("ComputeAuthTag: iv (nonce) = %x (%d)\n", nonce, len(nonce))
		debug.Printf("ComputeAuthTag: integrity  = %x (%d)\n", c.integrityKey, len(c.integrityKey))
	}

	buf := make([]byte, len(aad)+len(nonce)+len(ciphertext)+8)
	n := 0
	n += copy(buf, aad)
	n += copy(buf[n:], nonce)
	n += copy(buf[n:], ciphertext)
	binary.BigEndian.PutUint64(buf[n:], uint64(len(aad)*8))

	h := hmac.New(c.hash, c.integrityKey)
	h.Write(buf)
	s := h.Sum(nil)
	if debug.Enabled {
		debug.Printf("ComputeAuthTag: buf        = %x (%d)\n", buf, len(buf))
		debug.Printf("ComputeAuthTag: computed   = %x (%d)\n", s[:c.keysize], len(s[:c.keysize]))
	}
	return s[:c.tagsize]
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

	if debug.Enabled {
		debug.Printf("Seal: ciphertext = %x (%d)\n", ciphertext, len(ciphertext))
		debug.Printf("Seal: authtag    = %x (%d)\n", authtag, len(authtag))
		debug.Printf("Seal: ret        = %x (%d)\n", ret, len(ret))
	}
	return ret
}

// Open fulfills the crypto.AEAD interface
func (c AesCbcHmac) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(ciphertext) < c.keysize {
		return nil, errors.New("invalid ciphertext (too short)")
	}

	tagOffset := len(ciphertext) - c.tagsize
	if tagOffset%c.blockCipher.BlockSize() != 0 {
		return nil, fmt.Errorf(
			"invalid ciphertext (invalid length: %d %% %d != 0)",
			tagOffset,
			c.blockCipher.BlockSize(),
		)
	}
	tag := ciphertext[tagOffset:]
	ciphertext = ciphertext[:tagOffset]

	expectedTag := c.ComputeAuthTag(data, nonce, ciphertext)
	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
		if debug.Enabled {
			debug.Printf("provided tag = %x\n", tag)
			debug.Printf("expected tag = %x\n", expectedTag)
		}
		return nil, errors.New("invalid ciphertext (tag mismatch)")
	}

	cbc := cipher.NewCBCDecrypter(c.blockCipher, nonce)
	buf := make([]byte, tagOffset)
	cbc.CryptBlocks(buf, ciphertext)

	plaintext, err := padbuf.PadBuffer(buf).Unpad(c.blockCipher.BlockSize())
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate plaintext from decrypted blocks`)
	}
	ret := ensureSize(dst, len(plaintext))
	out := ret[len(dst):]
	copy(out, plaintext)
	return ret, nil
}
