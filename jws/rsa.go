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
		if err := RegisterSigner(alg, rsasigner{
			alg:  alg,
			hash: item.Hash,
			pss:  item.PSS,
		}); err != nil {
			panic(fmt.Sprintf("RegisterSigner failed: %v", err))
		}
		if err := RegisterVerifier(alg, rsaverifier{
			alg:  alg,
			hash: item.Hash,
			pss:  item.PSS,
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
		return jwsbb.SignCryptoSignerRaw(cs, raw, s.hash, options)
	}

	var privkey *rsa.PrivateKey
	if err := keyconv.RSAPrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`jws.RSASigner: invalid key type %T. rsa.PrivateKey is required: %w`, key, err)
	}
	return jwsbb.SignRSARaw(privkey, raw, s.hash, s.pss)
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

	return jwsbb.VerifyRSA(pubkey, payload, protected, signature, v.hash, v.pss, encoder, encodePayload)
}
