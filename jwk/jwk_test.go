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
	ks1 := &Set{}
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

	ks2, err := ParseSet(bytes.NewReader(buf))
	if !assert.NoError(t, err, "JSON unmarshal succeeded") {
		return
	}

	for _, use := range []string{"enc", "sig"} {
		for i := 0; i < 2; i++ {
			kid := use + strconv.Itoa(i)
			keys := ks2.LookupKeyId(kid)
			if !assert.Len(t, keys, 1, "Should be 1 key") {
				return
			}
			key1 := keys[0]

			pk1, ok := key1.(*RsaPrivateKey)
			if !assert.True(t, ok, "Should be RsaPrivateKey") {
				return
			}

			keys = ks1.LookupKeyId(kid)
			if !assert.Len(t, keys, 1, "Should be 1 key") {
				return
			}

			key2 := keys[0]
			pk2, ok := key2.(*RsaPrivateKey)
			if !assert.True(t, ok, "Should be RsaPrivateKey") {
				return
			}

			if !assert.Equal(t, pk2, pk1, "Keys should match") {
				return
			}
		}
	}
	spew.Dump(ks1, ks2)
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