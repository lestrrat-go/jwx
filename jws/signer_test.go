package jws_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jws/sign"
	"github.com/lestrrat-go/jwx/jws/verify"
	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	t.Run("Bad algorithm", func(t *testing.T) {
		_, err := jws.Sign([]byte(nil), jwa.SignatureAlgorithm("FooBar"), nil)
		if !assert.Error(t, err, "Unknown algorithm should return error") {
			return
		}
	})
	t.Run("No private key", func(t *testing.T) {
		_, err := jws.Sign([]byte{'a', 'b', 'c'}, jwa.RS256, nil)
		if !assert.Error(t, err, "Sign with no private key should return error") {
			return
		}
	})
	t.Run("RSA verify with no public key", func(t *testing.T) {
		_, err := jws.Verify([]byte(nil), jwa.RS256, nil)
		if !assert.Error(t, err, "Verify with no private key should return error") {
			return
		}
	})
	t.Run("RSA roundtrip", func(t *testing.T) {
		rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
		if !assert.NoError(t, err, "RSA key generated") {
			return
		}

		signer, err := sign.New(jwa.RS256)
		if !assert.NoError(t, err, `creating a signer should succeed`) {
			return
		}

		payload := []byte("Hello, world")

		signed, err := signer.Sign(payload, rsakey)
		if !assert.NoError(t, err, "Payload signed") {
			return
		}

		verifier, err := verify.New(jwa.RS256)
		if !assert.NoError(t, err, "creating a verifier should succeed") {
			return
		}

		if !assert.NoError(t, verifier.Verify(payload, signed, &rsakey.PublicKey), "Payload verified") {
			return
		}
	})
}
func TestSignMulti(t *testing.T) {
	rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.NoError(t, err, "RSA key generated") {
		return
	}

	dsakey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.NoError(t, err, "ECDSA key generated") {
		return
	}

	s1, err := sign.New(jwa.RS256)
	if !assert.NoError(t, err, "RSA Signer created") {
		return
	}
	var s1hdr jws.StandardHeaders
	s1hdr.Set(jws.KeyIDKey, "2010-12-29")

	s2, err := sign.New(jwa.ES256)
	if !assert.NoError(t, err, "DSA Signer created") {
		return
	}
	var s2hdr jws.StandardHeaders
	s2hdr.Set(jws.KeyIDKey, "e9bc097a-ce51-4036-9562-d2ade882db0d")

	v := strings.Join([]string{`{"iss":"joe",`, ` "exp":1300819380,`, ` "http://example.com/is_root":true}`}, "\r\n")
	m, err := jws.SignMulti([]byte(v),
		jws.WithSigner(s1, rsakey, &s1hdr, nil),
		jws.WithSigner(s2, dsakey, &s2hdr, nil),
	)
	if !assert.NoError(t, err, "jws.SignMulti should succeed") {
		return
	}

	t.Logf("%s", m)
}
