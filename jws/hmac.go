package jws

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

func init() {
	algs := map[jwa.SignatureAlgorithm]func() hash.Hash{
		jwa.HS256(): sha256.New,
		jwa.HS384(): sha512.New384,
		jwa.HS512(): sha512.New,
	}

	for alg, h := range algs {
		RegisterSigner(alg, hmacsigner{
			alg:   alg,
			hfunc: h,
		})
		RegisterVerifier(alg, hmacverifier{
			signer: hmacsigner{
				alg:   alg,
				hfunc: h,
			},
		})
	}
}

type hmacsigner struct {
	alg   jwa.SignatureAlgorithm
	hfunc func() hash.Hash
}

func (s hmacsigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

func (s hmacsigner) Do(payload, protected []byte, encoder Base64Encoder, encodePayload bool, key any) ([]byte, error) {
	var hmackey []byte
	if err := keyconv.ByteSliceKey(&hmackey, key); err != nil {
		return nil, fmt.Errorf(`jws.HMACSigner: invalid key type %T. []byte is required: %w`, key, err)
	}

	if len(hmackey) == 0 {
		return nil, fmt.Errorf(`jws.HMACSigner: missing key while signing payload`)
	}

	return jwsbb.SignHMAC(hmackey, payload, protected, s.hfunc, encoder, encodePayload)
}

type hmacverifier struct {
	signer hmacsigner
}

func (v hmacverifier) Algorithm() jwa.SignatureAlgorithm {
	return v.signer.Algorithm()
}

func (v hmacverifier) Do(payload, protected, signature []byte, encoder Base64Encoder, encodePayload bool, key any) error {
	expected, err := v.signer.Do(payload, protected, encoder, encodePayload, key)
	if err != nil {
		return fmt.Errorf(`jws.HMACVerifier: failed to generated signature: %w`, err)
	}

	if !hmac.Equal(signature, expected) {
		return fmt.Errorf(`jws.HMACVerifier: failed to match hmac signature`)
	}
	return nil
}
