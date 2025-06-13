package jws

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws/internal/keytype"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

var _ Signer2 = rsasigner{}
var _ Verifier2 = rsaverifier{}

func init() {
	algs := []jwa.SignatureAlgorithm{
		jwa.RS256(),
		jwa.RS384(),
		jwa.RS512(),
		jwa.PS256(),
		jwa.PS384(),
		jwa.PS512(),
	}

	for _, alg := range algs {
		h, pss, err := jwsbb.RSAHashFuncFor(alg.String())
		if err != nil {
			panic(fmt.Sprintf("jws.RSASigner: failed to get hash function for %s: %v", alg, err))
		}
		if err := RegisterSigner(alg, rsasigner{
			alg:  alg,
			hash: h,
			pss:  pss,
		}); err != nil {
			panic(fmt.Sprintf("RegisterSigner failed: %v", err))
		}
		if err := RegisterVerifier(alg, rsaverifier{
			alg:  alg,
			hash: h,
			pss:  pss,
		}); err != nil {
			panic(fmt.Sprintf("RegisterVerifier failed: %v", err))
		}
	}
}

type rsasigner struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	pss  bool // whether to use PSS padding
}

func (s rsasigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

func rsaGetSignerCryptoSignerKey(key any) (crypto.Signer, bool, error) {
	cs, isCryptoSigner := key.(crypto.Signer)
	if isCryptoSigner {
		if !keytype.IsValidRSAKey(key) {
			return nil, false, fmt.Errorf(`cannot use key of type %T`, key)
		}
		return cs, true, nil
	}
	return nil, false, nil
}

func (s rsasigner) Sign(key any, raw []byte) ([]byte, error) {
	cs, isCryptoSigner, err := rsaGetSignerCryptoSignerKey(key)
	if err != nil {
		return nil, fmt.Errorf(`jws.RSASigner: %w`, err)
	}
	if isCryptoSigner {
		var options crypto.SignerOpts = s.hash
		if s.pss {
			rsaopts := jwsbb.RSAPSSOptions(s.hash)
			options = &rsaopts
		}
		return jwsbb.SignCryptoSigner(cs, raw, s.hash, options)
	}

	var privkey *rsa.PrivateKey
	if err := keyconv.RSAPrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`jws.RSASigner: invalid key type %T. rsa.PrivateKey is required: %w`, key, err)
	}
	return jwsbb.SignRSA(privkey, raw, s.hash, s.pss)
}

type rsaverifier struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	pss  bool // whether to use PSS padding
}

func (v rsaverifier) Algorithm() jwa.SignatureAlgorithm {
	return v.alg
}
func (v rsaverifier) Verify(key any, payload, signature []byte) error {
	var pubkey *rsa.PublicKey

	if cs, ok := key.(crypto.Signer); ok {
		cpub := cs.Public()
		switch cpub := cpub.(type) {
		case rsa.PublicKey:
			pubkey = &cpub
		case *rsa.PublicKey:
			pubkey = cpub
		default:
			return fmt.Errorf(`jws.RSAVerifier: failed to retrieve rsa.PublicKey out of crypto.Signer %T`, key)
		}
	} else {
		if err := keyconv.RSAPublicKey(&pubkey, key); err != nil {
			return fmt.Errorf(`jws.RSAVerifier: failed to retrieve rsa.PublicKey out of %T: %w`, key, err)
		}
	}

	return jwsbb.VerifyRSA(pubkey, payload, signature, v.hash, v.pss)
}
