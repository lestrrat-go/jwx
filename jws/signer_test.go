package jws_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	t.Parallel()
	t.Run("Bad algorithm", func(t *testing.T) {
		t.Parallel()
		_, err := jws.Sign([]byte(nil), jws.WithKey(jwa.SignatureAlgorithm("FooBar"), nil))
		if !assert.Error(t, err, "Unknown algorithm should return error") {
			return
		}
	})
	t.Run("No private key", func(t *testing.T) {
		t.Parallel()
		_, err := jws.Sign([]byte{'a', 'b', 'c'}, jws.WithKey(jwa.RS256, nil))
		if !assert.Error(t, err, "Sign with no private key should return error") {
			return
		}
	})
	t.Run("RSA verify with no public key", func(t *testing.T) {
		t.Parallel()
		_, err := jws.Verify([]byte(nil), jws.WithKey(jwa.RS256, nil))
		if !assert.Error(t, err, "Verify with no private key should return error") {
			return
		}
	})
	t.Run("RSA roundtrip", func(t *testing.T) {
		t.Parallel()
		rsakey, err := jwxtest.GenerateRsaKey()
		if !assert.NoError(t, err, "RSA key generated") {
			return
		}

		signer, err := jws.NewSigner(jwa.RS256)
		if !assert.NoError(t, err, `creating a signer should succeed`) {
			return
		}

		payload := []byte("Hello, world")

		signed, err := signer.Sign(payload, rsakey)
		if !assert.NoError(t, err, "Payload signed") {
			return
		}

		verifier, err := jws.NewVerifier(jwa.RS256)
		if !assert.NoError(t, err, "creating a verifier should succeed") {
			return
		}

		if !assert.NoError(t, verifier.Verify(payload, signed, &rsakey.PublicKey), "Payload verified") {
			return
		}
	})
}

func TestSignMulti(t *testing.T) {
	rsakey, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, "RSA key generated") {
		return
	}

	dsakey, err := jwxtest.GenerateEcdsaKey(jwa.P521)
	if !assert.NoError(t, err, "ECDSA key generated") {
		return
	}

	s1hdr := jws.NewHeaders()
	s1hdr.Set(jws.KeyIDKey, "2010-12-29")

	s2hdr := jws.NewHeaders()
	s2hdr.Set(jws.KeyIDKey, "e9bc097a-ce51-4036-9562-d2ade882db0d")

	v := strings.Join([]string{`{"iss":"joe",`, ` "exp":1300819380,`, ` "http://example.com/is_root":true}`}, "\r\n")
	m, err := jws.Sign([]byte(v),
		jws.WithJSON(),
		jws.WithKey(jwa.RS256, rsakey, jws.WithPublicHeaders(s1hdr)),
		jws.WithKey(jwa.ES256, dsakey, jws.WithPublicHeaders(s2hdr)),
	)
	if !assert.NoError(t, err, "jws.SignMulti should succeed") {
		return
	}

	t.Logf("%s", m)
}
