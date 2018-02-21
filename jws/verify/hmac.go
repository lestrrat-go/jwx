package verify

import (
	"crypto/hmac"
	"encoding/base64"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws/sign"
	pdebug "github.com/lestrrat-go/pdebug"
	"github.com/pkg/errors"
)

func newHMAC(alg jwa.SignatureAlgorithm) (*HMACVerifier, error) {
	s, err := sign.New(alg)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate HMAC signer`)
	}
	return &HMACVerifier{signer: s}, nil
}

func (v HMACVerifier) Verify(payload, signature []byte, key interface{}) (err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("HMACVerifier.Verify").BindError(&err)
		defer g.End()
	}

	expected, err := v.signer.Sign(payload, key)
	if err != nil {
		return errors.Wrap(err, `failed to generated signature`)
	}

	if pdebug.Enabled {
		pdebug.Printf("generated signature %s", base64.RawURLEncoding.EncodeToString(signature))
		pdebug.Printf("expected  signature %s", base64.RawURLEncoding.EncodeToString(expected))
	}

	if !hmac.Equal(signature, expected) {
		return errors.New(`failed to match hmac signature`)
	}
	return nil
}
