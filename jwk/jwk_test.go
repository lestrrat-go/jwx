package jwk

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestJwksRoundtrip(t *testing.T) {
	ks1 := &KeySet{}
	for _, use := range []string{"enc", "sig"} {
		for i := 0; i < 2; i++ {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if !assert.NoError(t, err, "RSA key generated") {
				return
			}

			k, err := NewRsaPrivateKey(key)
			if !assert.NoError(t, err, "JWK RSA key generated") {
				return
			}

			k.Use = use
			k.KeyId = use + strconv.Itoa(i)

			ks1.Keys = append(ks1.Keys, k)
		}
	}

	buf, err := json.MarshalIndent(ks1, "", "  ")
	if !assert.NoError(t, err, "JSON marshal succeeded") {
		return
	}

	ks2, err := ParseKeySet(bytes.NewReader(buf))
	if !assert.NoError(t, err, "JSON unmarshal succeeded") {
		return
	}

	t.Logf("%#v", ks2)
}

func TestRsaPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.NoError(t, err, "RSA key generated") {
		return
	}

	k1, err := NewRsaPrivateKey(key)
	if !assert.NoError(t, err, "JWK RSA key generated") {
		return
	}

	jsonbuf, err := json.MarshalIndent(k1, "", "  ")
	if !assert.NoError(t, err, "Marshal to JSON succeeded") {
		return
	}

	t.Logf("%s", jsonbuf)

	k2 := &RsaPrivateKey{}
	if !assert.NoError(t, json.Unmarshal(jsonbuf, k2), "Unmarshal from JSON succeeded") {
		return
	}

	if !assert.Equal(t, k1, k2, "keys match") {
		return
	}

	k3, err := Parse(bytes.NewReader(jsonbuf))
	if !assert.NoError(t, err, "Parse should succeed") {
		return
	}

	if !assert.Equal(t, k1, k3, "keys match") {
		spew.Dump(k1, k3)
		return
	}
}