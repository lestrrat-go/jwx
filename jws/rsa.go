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

func init() {
	data := map[jwa.SignatureAlgorithm]struct {
		Hash crypto.Hash
		PSS  bool
	}{
		jwa.RS256(): {
			Hash: crypto.SHA256,
		},
		jwa.RS384(): {
			Hash: crypto.SHA384,
		},
		jwa.RS512(): {
			Hash: crypto.SHA512,
		},
		jwa.PS256(): {
			Hash: crypto.SHA256,
			PSS:  true,
		},
		jwa.PS384(): {
			Hash: crypto.SHA384,
			PSS:  true,
		},
		jwa.PS512(): {
			Hash: crypto.SHA512,
			PSS:  true,
		},
	}

	for alg, item := range data {
		RegisterSigner2(alg, rsasigner{
			alg:  alg,
			hash: item.Hash,
			pss:  item.PSS,
		})
		RegisterVerifier2(alg, rsaverifier{
			alg:  alg,
			hash: item.Hash,
			pss:  item.PSS,
		})
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

func (s rsasigner) Do(payload, protected []byte, encoder Base64Encoder, encodePayload bool, key any) ([]byte, error) {
	signer, ok := key.(crypto.Signer)
	if ok {
		if !keytype.IsValidRSAKey(key) {
			return nil, fmt.Errorf(`cannot use key of type %T to generate RSA based signatures`, key)
		}

		var options crypto.SignerOpts = s.hash
		if s.pss {
			rsaopts := jwsbb.RSAPSSOptions(s.hash)
			options = &rsaopts
		}

		return jwsbb.SignCryptoSigner(payload, protected, s.hash, signer, options, encoder, encodePayload)
	}

	var privkey *rsa.PrivateKey
	if err := keyconv.RSAPrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`jws.RSASigner: invalid key type %T. rsa.PrivateKey is required: %w`, key, err)
	}
	return jwsbb.SignRSA(payload, protected, s.hash, s.pss, encoder, encodePayload, privkey)
}

type rsaverifier struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	pss  bool // whether to use PSS padding
}

func (v rsaverifier) Algorithm() jwa.SignatureAlgorithm {
	return v.alg
}
func (v rsaverifier) Do(payload, protected, signature []byte, encoder Base64Encoder, encodePayload bool, key any) error {
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

	return jwsbb.VerifyRSA(payload, protected, signature, v.hash, v.pss, encoder, encodePayload, pubkey)
}
