package jws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/internal/keyconv"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

var rsaSigners map[jwa.SignatureAlgorithm]*rsaSigner
var rsaVerifiers map[jwa.SignatureAlgorithm]*rsaVerifier

func init() {
	algs := map[jwa.SignatureAlgorithm]struct {
		Hash crypto.Hash
		PSS  bool
	}{
		jwa.RS256: {
			Hash: crypto.SHA256,
		},
		jwa.RS384: {
			Hash: crypto.SHA384,
		},
		jwa.RS512: {
			Hash: crypto.SHA512,
		},
		jwa.PS256: {
			Hash: crypto.SHA256,
			PSS:  true,
		},
		jwa.PS384: {
			Hash: crypto.SHA384,
			PSS:  true,
		},
		jwa.PS512: {
			Hash: crypto.SHA512,
			PSS:  true,
		},
	}

	rsaSigners = make(map[jwa.SignatureAlgorithm]*rsaSigner)
	rsaVerifiers = make(map[jwa.SignatureAlgorithm]*rsaVerifier)
	for alg, item := range algs {
		rsaSigners[alg] = &rsaSigner{
			alg:  alg,
			hash: item.Hash,
			pss:  item.PSS,
		}
		rsaVerifiers[alg] = &rsaVerifier{
			alg:  alg,
			hash: item.Hash,
			pss:  item.PSS,
		}
	}
}

type rsaSigner struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	pss  bool
}

func newRSASigner(alg jwa.SignatureAlgorithm) Signer {
	return rsaSigners[alg]
}

func (rs *rsaSigner) Algorithm() jwa.SignatureAlgorithm {
	return rs.alg
}

func (rs *rsaSigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	if key == nil {
		return nil, errors.New(`missing private key while signing payload`)
	}

	var signer crypto.Signer
	switch key := key.(type) {
	case ExternalSigner:
		// an external signer is a signer who knows what to do on its own.
		// it simply returns the signature by being passed the payload
		return key.Sign(payload)
	case crypto.Signer:
		// if given an *rsa.PrivateKey, we would be falling here
		signer = key
	default:
		var privkey rsa.PrivateKey
		if err := keyconv.RSAPrivateKey(&privkey, key); err != nil {
			return nil, errors.Wrapf(err, `failed to retrieve rsa.PrivateKey out of %T`, key)
		}
		// rsa.PrivateKey is an instance of crypto.Signer. therefore it knows
		// how to Sign()
		signer = &privkey
	}

	var opts crypto.SignerOpts = rs.hash
	if rs.pss {
		opts = &rsa.PSSOptions{
			Hash:       rs.hash,
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
	}

	h := rs.hash.New()
	if _, err := h.Write(payload); err != nil {
		return nil, errors.Wrap(err, "failed to write payload to hash")
	}
	return signer.Sign(rand.Reader, h.Sum(nil), opts)
}

type rsaVerifier struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	pss  bool
}

func newRSAVerifier(alg jwa.SignatureAlgorithm) Verifier {
	return rsaVerifiers[alg]
}

func (rv *rsaVerifier) Verify(payload, signature []byte, key interface{}) error {
	if key == nil {
		return errors.New(`missing public key while verifying payload`)
	}

	if v, ok := key.(ExternalVerifier); ok {
		return v.Verify(payload, signature)
	}

	var pubkey rsa.PublicKey
	if err := keyconv.RSAPublicKey(&pubkey, key); err != nil {
		return errors.Wrapf(err, `failed to retrieve rsa.PublicKey out of %T`, key)
	}

	h := rv.hash.New()
	if _, err := h.Write(payload); err != nil {
		return errors.Wrap(err, "failed to write payload to hash")
	}

	if rv.pss {
		return rsa.VerifyPSS(&pubkey, rv.hash, h.Sum(nil), signature, nil)
	}
	return rsa.VerifyPKCS1v15(&pubkey, rv.hash, h.Sum(nil), signature)
}
