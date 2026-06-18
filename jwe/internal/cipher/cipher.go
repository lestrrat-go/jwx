package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/aescbc"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
)

var gcm = &gcmFetcher{}
var cbc = &cbcFetcher{}

func (f gcmFetcher) Fetch(key []byte, size int) (cipher.AEAD, error) {
	if len(key) != size {
		return nil, fmt.Errorf(`key size (%d) does not match expected key size (%d)`, len(key), size)
	}
	aescipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf(`cipher: failed to create AES cipher for GCM: %w`, err)
	}

	aead, err := cipher.NewGCM(aescipher)
	if err != nil {
		return nil, fmt.Errorf(`failed to create GCM for cipher: %w`, err)
	}
	return aead, nil
}

func (f cbcFetcher) Fetch(key []byte, size int) (cipher.AEAD, error) {
	if len(key) != size {
		return nil, fmt.Errorf(`key size (%d) does not match expected key size (%d)`, len(key), size)
	}
	aead, err := aescbc.New(key, aes.NewCipher)
	if err != nil {
		return nil, fmt.Errorf(`cipher: failed to create AES cipher for CBC: %w`, err)
	}
	return aead, nil
}

func (c AesContentCipher) KeySize() int {
	return c.keysize
}

func (c AesContentCipher) TagSize() int {
	return c.tagsize
}

func NewAES(alg string) (*AesContentCipher, error) {
	var keysize int
	var tagsize int
	var fetcher Fetcher
	switch alg {
	case tokens.A128GCM:
		keysize = 16
		tagsize = 16
		fetcher = gcm
	case tokens.A192GCM:
		keysize = 24
		tagsize = 16
		fetcher = gcm
	case tokens.A256GCM:
		keysize = 32
		tagsize = 16
		fetcher = gcm
	case tokens.A128CBC_HS256:
		tagsize = 16
		keysize = tagsize * 2
		fetcher = cbc
	case tokens.A192CBC_HS384:
		tagsize = 24
		keysize = tagsize * 2
		fetcher = cbc
	case tokens.A256CBC_HS512:
		tagsize = 32
		keysize = tagsize * 2
		fetcher = cbc
	default:
		return nil, fmt.Errorf("failed to create AES content cipher: invalid algorithm (%s)", alg)
	}

	return &AesContentCipher{
		keysize: keysize,
		tagsize: tagsize,
		fetch:   fetcher,
	}, nil
}

func (c AesContentCipher) Encrypt(cek, plaintext, aad []byte) (iv, ciphertxt, tag []byte, err error) {
	var aead cipher.AEAD
	aead, err = c.fetch.Fetch(cek, c.keysize)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(`failed to fetch AEAD: %w`, err)
	}

	// CBC+HMAC's Seal may panic (buffer size limits, auth tag errors),
	// so we must recover. GCM's Seal from the stdlib does not panic
	// with valid inputs, but we protect uniformly for safety.
	defer func() {
		if e := recover(); e != nil {
			switch v := e.(type) {
			case error:
				err = fmt.Errorf(`failed to encrypt: %w`, v)
			default:
				err = fmt.Errorf("failed to encrypt: %s", v)
			}
		}
	}()

	if c.NonceGenerator != nil {
		iv, err = c.NonceGenerator(aead.NonceSize())
		if err != nil {
			return nil, nil, nil, fmt.Errorf(`failed to generate nonce: %w`, err)
		}
	} else {
		bs, err := keygen.Random(aead.NonceSize())
		if err != nil {
			return nil, nil, nil, fmt.Errorf(`failed to generate random nonce: %w`, err)
		}
		iv = bs.Bytes()
	}

	combined := aead.Seal(nil, iv, plaintext, aad)
	tagoffset := len(combined) - c.TagSize()

	ciphertxt = combined[:tagoffset:tagoffset]
	tag = combined[tagoffset:]

	return
}

func (c AesContentCipher) Decrypt(cek, iv, ciphertxt, tag, aad []byte) (plaintext []byte, err error) {
	aead, err := c.fetch.Fetch(cek, c.keysize)
	if err != nil {
		return nil, fmt.Errorf(`failed to fetch AEAD data: %w`, err)
	}

	// CBC+HMAC's Open may panic (buffer size limits), so we must recover.
	defer func() {
		if e := recover(); e != nil {
			switch v := e.(type) {
			case error:
				err = fmt.Errorf(`failed to decrypt: %w`, v)
			default:
				err = fmt.Errorf("failed to decrypt: %s", v)
			}
		}
	}()

	// Enforce the AEAD wire tag and IV lengths before concatenating. Without
	// this, bytes can be shifted between the wire ciphertext and tag fields to
	// produce a byte-identical AEAD input, yielding serialized ciphertext<->tag
	// malleability (exploitable on AES-GCM).
	if len(tag) != c.TagSize() {
		return nil, fmt.Errorf(`failed to decrypt: invalid tag size (got %d, expected %d)`, len(tag), c.TagSize())
	}
	if len(iv) != aead.NonceSize() {
		return nil, fmt.Errorf(`failed to decrypt: invalid iv size (got %d, expected %d)`, len(iv), aead.NonceSize())
	}

	combined := make([]byte, len(ciphertxt)+len(tag))
	copy(combined, ciphertxt)
	copy(combined[len(ciphertxt):], tag)

	plaintext, err = aead.Open(nil, iv, combined, aad)
	if err != nil {
		return nil, fmt.Errorf(`aead.Open failed: %w`, err)
	}
	return plaintext, nil
}
