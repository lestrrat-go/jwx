package jws

import (
	"fmt"
	"hash"

	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

var _ Signer2 = hmacsigner{}
var _ Verifier2 = hmacverifier{}

func init() {
	algs := []jwa.SignatureAlgorithm{
		jwa.HS256(),
		jwa.HS384(),
		jwa.HS512(),
	}

	for _, alg := range algs {
		h, err := jwsbb.HMACHashFuncFor(alg.String())
		if err != nil {
			panic(fmt.Sprintf("jws.HMACSigner: failed to get hash function for %s: %v", alg, err))
		}

		/*
			if err := RegisterSigner(alg, hmacsigner{
				alg:   alg,
				hfunc: h,
			}); err != nil {
				panic(fmt.Sprintf("RegisterSigner failed: %v", err))
			}*/
		if err := RegisterVerifier(alg, hmacverifier{
			alg:   alg,
			hfunc: h,
		}); err != nil {
			panic(fmt.Sprintf("RegisterVerifier failed: %v", err))
		}
	}
}

func toHMACKey(dst *[]byte, key any) error {
	if err := keyconv.ByteSliceKey(dst, key); err != nil {
		return fmt.Errorf(`jws.toHMACKey: invalid key type %T. []byte is required: %w`, key, err)
	}

	if len(*dst) == 0 {
		return fmt.Errorf(`jws.toHMACKey: missing key while signing payload`)
	}
	return nil
}

type hmacsigner struct {
	alg   jwa.SignatureAlgorithm
	hfunc func() hash.Hash
}

func (s hmacsigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

func (s hmacsigner) Sign(key any, raw []byte) ([]byte, error) {
	var hmackey []byte
	if err := toHMACKey(&hmackey, key); err != nil {
		return nil, fmt.Errorf(`jws.HMACSigner: %w`, err)
	}

	signature, err := jwsbb.SignHMAC(hmackey, raw, s.hfunc)
	if err != nil {
		return nil, fmt.Errorf(`jws.HMACSigner: failed to generate signature: %w`, err)
	}
	return signature, nil
}

type hmacverifier struct {
	alg   jwa.SignatureAlgorithm
	hfunc func() hash.Hash
}

func (v hmacverifier) Algorithm() jwa.SignatureAlgorithm {
	return v.alg
}

func (v hmacverifier) Verify(key any, payload, signature []byte) error {
	var hmackey []byte
	if err := toHMACKey(&hmackey, key); err != nil {
		return fmt.Errorf(`jws.HMACVerifier: %w`, err)
	}

	return jwsbb.VerifyHMAC(hmackey, payload, signature, v.hfunc)
}
