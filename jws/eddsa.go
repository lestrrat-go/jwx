package jws

import (
	"crypto"
	"crypto/ed25519"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws/internal/keytype"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

var _ Signer2 = eddsasigner{}
var _ Verifier2 = eddsaverifier{}

func init() {
	if err := RegisterSigner(jwa.EdDSA(), eddsasigner{
		alg: jwa.EdDSA(),
	}); err != nil {
		panic(fmt.Sprintf("RegisterSigner failed: %v", err))
	}
	if err := RegisterVerifier(jwa.EdDSA(), eddsaverifier{
		alg: jwa.EdDSA(),
	}); err != nil {
		panic(fmt.Sprintf("RegisterVerifier failed: %v", err))
	}
}

type eddsasigner struct {
	alg jwa.SignatureAlgorithm
}

func (s eddsasigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

func eddsaGetSigner(key any) (crypto.Signer, error) {
	// The ed25519.PrivateKey object implements crypto.Signer, so we should
	// simply accept a crypto.Signer here.
	signer, ok := key.(crypto.Signer)
	if ok {
		if !keytype.IsValidEDDSAKey(key) {
			return nil, fmt.Errorf(`cannot use key of type %T to generate EdDSA based signatures`, key)
		}
		return signer, nil
	}

	// This fallback exists for cases when jwk.Key was passed, or
	// users gave us a pointer instead of non-pointer, etc.
	var privkey ed25519.PrivateKey
	if err := keyconv.Ed25519PrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`failed to retrieve ed25519.PrivateKey out of %T: %w`, key, err)
	}
	return privkey, nil
}

func (s eddsasigner) Sign(payload, protected []byte, encoder Base64Encoder, encodePayload bool, key interface{}) ([]byte, error) {
	signer, err := eddsaGetSigner(key)
	if err != nil {
		return nil, fmt.Errorf(`jws.EdDSASigner: %w`, err)
	}

	return jwsbb.SignCryptoSigner(signer, payload, protected, crypto.Hash(0), crypto.Hash(0), encoder, encodePayload)
}

func (s eddsasigner) SignRaw(key any, raw []byte) ([]byte, error) {
	signer, err := eddsaGetSigner(key)
	if err != nil {
		return nil, fmt.Errorf(`jws.EdDSASigner: %w`, err)
	}

	return jwsbb.SignCryptoSignerRaw(signer, raw, crypto.Hash(0), crypto.Hash(0))
}

type eddsaverifier struct {
	alg jwa.SignatureAlgorithm
}

func (v eddsaverifier) Algorithm() jwa.SignatureAlgorithm {
	return v.alg
}

func (v eddsaverifier) Do(payload, protected, signature []byte, encoder Base64Encoder, encodePayload bool, key interface{}) error {
	var pubkey ed25519.PublicKey
	signer, ok := key.(crypto.Signer)
	if ok {
		v := signer.Public()
		pubkey, ok = v.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf(`expected crypto.Signer.Public() to return ed25519.PublicKey, but got %T`, v)
		}
	} else {
		if err := keyconv.Ed25519PublicKey(&pubkey, key); err != nil {
			return fmt.Errorf(`failed to retrieve ed25519.PublicKey out of %T: %w`, key, err)
		}
	}

	return jwsbb.VerifyEdDSA(pubkey, payload, protected, signature, encoder, encodePayload)
}
