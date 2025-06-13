package jws

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws/internal/keytype"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

var _ Signer2 = ecdsasigner{}
var _ Verifier2 = ecdsaverifier{}

func init() {
	algs := map[jwa.SignatureAlgorithm]crypto.Hash{
		jwa.ES256():  crypto.SHA256,
		jwa.ES384():  crypto.SHA384,
		jwa.ES512():  crypto.SHA512,
		jwa.ES256K(): crypto.SHA256,
	}

	for alg, hash := range algs {
		if err := RegisterSigner(alg, ecdsasigner{
			alg:  alg,
			hash: hash,
		}); err != nil {
			panic(fmt.Sprintf("RegisterSigner failed: %v", err))
		}

		if err := RegisterVerifier(alg, ecdsaverifier{
			alg:  alg,
			hash: hash,
		}); err != nil {
			panic(fmt.Sprintf("RegisterVerifier failed: %v", err))
		}
	}
}

type ecdsasigner struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
}

func (es ecdsasigner) Algorithm() jwa.SignatureAlgorithm {
	return es.alg
}

func ecdsaGetSignerKey(key any) (*ecdsa.PrivateKey, crypto.Signer, bool, error) {
	cs, isCryptoSigner := key.(crypto.Signer)
	if isCryptoSigner {
		if !keytype.IsValidECDSAKey(key) {
			return nil, nil, false, fmt.Errorf(`cannot use key of type %T`, key)
		}
		switch key.(type) {
		case ecdsa.PrivateKey, *ecdsa.PrivateKey:
			// if it's ecdsa.PrivateKey, it's more efficient to
			// go through the non-crypto.Signer route. Set isCryptoSigner to false
			isCryptoSigner = false
		}
	}

	if isCryptoSigner {
		return nil, cs, true, nil
	}

	var privkey *ecdsa.PrivateKey
	if err := keyconv.ECDSAPrivateKey(&privkey, key); err != nil {
		return nil, nil, false, fmt.Errorf(`invalid key type %T. ecdsa.PrivateKey is required: %w`, key, err)
	}
	return privkey, nil, false, nil
}

func (es ecdsasigner) Sign(key any, raw []byte) ([]byte, error) {
	privkey, cs, isCryptoSigner, err := ecdsaGetSignerKey(key)
	if err != nil {
		return nil, fmt.Errorf(`jws.ECDSASigner: %w`, err)
	}
	if isCryptoSigner {
		return jwsbb.SignECDSACryptoSigner(cs, raw, es.hash)
	}
	return jwsbb.SignECDSA(privkey, raw, es.hash)
}

type ecdsaverifier struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
}

func (ev ecdsaverifier) Algorithm() jwa.SignatureAlgorithm {
	return ev.alg
}

func ecdsaGetVerifierKey(key any) (*ecdsa.PublicKey, crypto.Signer, bool, error) {
	cs, isCryptoSigner := key.(crypto.Signer)
	if isCryptoSigner {
		if !keytype.IsValidECDSAKey(key) {
			return nil, nil, false, fmt.Errorf(`cannot use key of type %T`, key)
		}
		switch key.(type) {
		case ecdsa.PublicKey, *ecdsa.PublicKey:
			// if it's ecdsa.PublicKey, it's more efficient to
			// go through the non-crypto.Signer route. Set isCryptoSigner to false
			isCryptoSigner = false
		}
	}

	if isCryptoSigner {
		return nil, cs, true, nil
	}

	var pubkey *ecdsa.PublicKey
	if err := keyconv.ECDSAPublicKey(&pubkey, key); err != nil {
		return nil, nil, false, fmt.Errorf(`invalid key type %T. ecdsa.PublicKey is required: %w`, key, err)
	}

	return pubkey, nil, false, nil
}

func (ev ecdsaverifier) Verify(key any, payload, signature []byte) error {
	pubkey, cs, isCryptoSigner, err := ecdsaGetVerifierKey(key)
	if err != nil {
		return fmt.Errorf(`jws.ECDSAVerifier: %w`, err)
	}
	if isCryptoSigner {
		return jwsbb.VerifyECDSACryptoSigner(cs, payload, signature, ev.hash)
	}
	return jwsbb.VerifyECDSA(pubkey, payload, signature, ev.hash)
}
