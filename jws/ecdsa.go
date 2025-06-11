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

func init() {
	algs := map[jwa.SignatureAlgorithm]crypto.Hash{
		jwa.ES256():  crypto.SHA256,
		jwa.ES384():  crypto.SHA384,
		jwa.ES512():  crypto.SHA512,
		jwa.ES256K(): crypto.SHA256,
	}

	for alg, hash := range algs {
		RegisterSigner(alg, ecdsasigner{
			alg:  alg,
			hash: hash,
		})

		RegisterVerifier(alg, ecdsaverifier{
			alg:  alg,
			hash: hash,
		})
	}
}

type ecdsasigner struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
}

func (es ecdsasigner) Create() (Signer, error) {
	return nil, fmt.Errorf(`jws.ECDSASigner does not support Create() method`)
}

func (es ecdsasigner) Algorithm() jwa.SignatureAlgorithm {
	return es.alg
}

func (es ecdsasigner) Do(payload, protected []byte, encoder Base64Encoder, encodePayload bool, key any) ([]byte, error) {
	cs, isCryptoSigner := key.(crypto.Signer)
	if isCryptoSigner {
		if !keytype.IsValidECDSAKey(key) {
			return nil, fmt.Errorf(`cannot use key of type %T to generate ECDSA based signatures`, key)
		}
		switch key.(type) {
		case ecdsa.PrivateKey, *ecdsa.PrivateKey:
			// if it's ecdsa.PrivateKey, it's more efficient to
			// go through the non-crypto.Signer route. Set isCryptoSigner to false
			isCryptoSigner = false
		}
	}

	if isCryptoSigner {
		return jwsbb.SignECDSACryptoSigner(payload, protected, es.hash, encoder, encodePayload, cs)
	}

	var privkey *ecdsa.PrivateKey
	if err := keyconv.ECDSAPrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`jws.ECDSASigner: invalid key type %T. ecdsa.PrivateKey is required: %w`, key, err)
	}
	return jwsbb.SignECDSA(payload, protected, es.hash, encoder, encodePayload, privkey)
}

type ecdsaverifier struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
}

func (ecdsaverifier) Create() (Verifier, error) {
	return nil, fmt.Errorf(`jws.ECDSAVerifier does not support Create() method`)
}

func (ev ecdsaverifier) Algorithm() jwa.SignatureAlgorithm {
	return ev.alg
}

func (ev ecdsaverifier) Do(payload, protected []byte, signature []byte, encoder Base64Encoder, encodePayload bool, key any) error {
	cs, isCryptoSigner := key.(crypto.Signer)
	if isCryptoSigner {
		if !keytype.IsValidECDSAKey(key) {
			return fmt.Errorf(`cannot use key of type %T to verify ECDSA based signatures`, key)
		}
		switch key.(type) {
		case ecdsa.PublicKey, *ecdsa.PublicKey:
			// if it's ecdsa.PublicKey, it's more efficient to
			// go through the non-crypto.Signer route. Set isCryptoSigner to false
			isCryptoSigner = false
		}
	}

	if isCryptoSigner {
		return jwsbb.VerifyECDSACryptoSigner(payload, protected, signature, ev.hash, encoder, encodePayload, cs)
	}

	var pubkey *ecdsa.PublicKey
	if err := keyconv.ECDSAPublicKey(&pubkey, key); err != nil {
		return fmt.Errorf(`jws.ECDSAVerifier: invalid key type %T. ecdsa.PublicKey is required: %w`, key, err)
	}
	return jwsbb.VerifyECDSA(payload, protected, signature, ev.hash, encoder, encodePayload, pubkey)
}
