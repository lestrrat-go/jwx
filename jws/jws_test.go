package jws

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/stretchr/testify/assert"
)

func TestCompact_EncodeDecode(t *testing.T) {
	for _, alg := range []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512} {
		t.Logf("alg = %s", alg)
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if !assert.NoError(t, err, "RSA key generated") {
			return
		}

		signer := RSASign{PrivateKey: key, Algorithm: alg}
		hdr := &Header{
			Algorithm: alg,
		}

		payload := buffer.Buffer("Hello, World!")
		buf, err := Encode(hdr, payload, signer)
		if !assert.NoError(t, err, "(%s) Encode is successful", alg) {
			return
		}

		c, err := ParseCompact(buf)
		if !assert.NoError(t, err, "ParseCompact is successful") {
			return
		}

		h2 := Header{}
		if !assert.NoError(t, c.Header.JsonDecode(&h2), "Can JSON decode header") {
			return
		}

		if !assert.Equal(t, buffer.Buffer("Hello, World!"), c.Payload, "Payload is decoded") {
			return
		}

		if !assert.NoError(t, c.Verify(signer), "Verify is successful") {
			return
		}
	}
}
