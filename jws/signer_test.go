package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/stretchr/testify/assert"
)

func TestMultiSigner(t *testing.T) {
	rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.NoError(t, err, "RSA key generated") {
		return
	}

	dsakey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.NoError(t, err, "ECDSA key generated") {
		return
	}

	ms := &MultiSign{}

	s1, err := NewRsaSign(RS256, rsakey)
	if !assert.NoError(t, err, "RSA Signer created") {
		return
	}
	s1.KeyId = "2010-12-29"
	ms.AddSigner(s1)

	s2, err := NewEcdsaSign(ES256, dsakey)
	if !assert.NoError(t, err, "DSA Signer created") {
		return
	}
	s2.KeyId = "e9bc097a-ce51-4036-9562-d2ade882db0d"
	ms.AddSigner(s2)

	v := strings.Join([]string{`{"iss":"joe",`, ` "exp":1300819380,`, ` "http://example.com/is_root":true}`}, "\r\n")
	m, err := ms.MultiSign(buffer.Buffer(v))
	if !assert.NoError(t, err, "MultiSign succeeded") {
		return
	}

	jsonbuf, _ := json.MarshalIndent(m, "", "  ")
	t.Logf("%s", jsonbuf)
}