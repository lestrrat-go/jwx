package aescbc

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVectorsAESCBC128(t *testing.T) {
	// Source: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-29#appendix-A.2
	plaintext := []byte{
		76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
		112, 114, 111, 115, 112, 101, 114, 46}

	aad := []byte{
		101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
		120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
		74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
		50, 73, 110, 48}

	ciphertext := []byte{
		40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
		75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
		112, 56, 102}

	authtag := []byte{
		246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100,
		191}

	key := []byte{
		4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206,
		107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207}

	nonce := []byte{
		3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101}

	enc, err := New(key, aes.NewCipher)
	out := enc.Seal(nil, nonce, plaintext, aad)
	if !assert.NoError(t, err, "enc.Seal") {
		return
	}

	if !assert.Equal(t, ciphertext, out[:len(out)-enc.keysize], "Ciphertext tag should match") {
		return
	}

	if !assert.Equal(t, authtag, out[len(out)-enc.keysize:], "Auth tag should match") {
		return
	}

	out, err = enc.Open(nil, nonce, out, aad)
	if !assert.NoError(t, err, "Open should succeed") {
		return
	}

	if !assert.Equal(t, plaintext, out, "Open should get us original text") {
		return
	}
}
