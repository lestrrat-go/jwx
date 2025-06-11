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

func init() {
	RegisterSigner(jwa.EdDSA(), eddsasigner{
		alg: jwa.EdDSA(),
	})
	RegisterVerifier(jwa.EdDSA(), eddsaverifier{
		alg: jwa.EdDSA(),
	})
}

type eddsasigner struct {
	alg jwa.SignatureAlgorithm
}

func (s eddsasigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

func (s eddsasigner) Do(payload, protected []byte, encoder Base64Encoder, encodePayload bool, key interface{}) ([]byte, error) {
	// The ed25519.PrivateKey object implements crypto.Signer, so we should
	// simply accept a crypto.Signer here.
	signer, ok := key.(crypto.Signer)
	if ok {
		if !keytype.IsValidEDDSAKey(key) {
			return nil, fmt.Errorf(`cannot use key of type %T to generate EdDSA based signatures`, key)
		}
	} else {
		// This fallback exists for cases when jwk.Key was passed, or
		// users gave us a pointer instead of non-pointer, etc.
		var privkey ed25519.PrivateKey
		if err := keyconv.Ed25519PrivateKey(&privkey, key); err != nil {
			return nil, fmt.Errorf(`failed to retrieve ed25519.PrivateKey out of %T: %w`, key, err)
		}
		signer = privkey
	}

	return jwsbb.SignCryptoSigner(signer, payload, protected, crypto.Hash(0), crypto.Hash(0), encoder, encodePayload)
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
