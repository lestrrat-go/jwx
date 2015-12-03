package concatkdf

import (
	"crypto"
	"testing"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/stretchr/testify/assert"
)

// https://tools.ietf.org/html/rfc7518#appendix-C
func TestAppendix(t *testing.T) {
	z := []byte{158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196}
	alg := []byte(jwa.A128GCM.String())
	apu := []byte{65, 108, 105, 99, 101}
	apv := []byte{66, 111, 98}
	pub := []byte{0, 0, 0, 128}
	priv := []byte(nil)
	expected := []byte{86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26}

	kdf := New(crypto.SHA256, alg, z, apu, apv, pub, priv)

	out := make([]byte, 16) // 128bits

	n, err := kdf.Read(out[:5])
	if !assert.Equal(t, 5, n, "first read bytes matches") ||
		!assert.NoError(t, err, "first read successful") {
		return
	}

	n, err = kdf.Read(out[5:])
	if !assert.Equal(t, 11, n, "second read bytes matches") ||
		!assert.NoError(t, err, "second read successful") {
		return
	}

	if !assert.Equal(t, expected, out, "generated value matches") {
		return
	}
}
