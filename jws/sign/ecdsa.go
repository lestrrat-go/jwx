package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

var ecdsaSignFuncs = map[jwa.SignatureAlgorithm]ecdsaSignFunc{}

func init() {
	algs := map[jwa.SignatureAlgorithm]crypto.Hash{
		jwa.ES256: crypto.SHA256,
		jwa.ES384: crypto.SHA384,
		jwa.ES512: crypto.SHA512,
	}

	for alg, h := range algs {
		ecdsaSignFuncs[alg] = makeECDSASignFunc(h)
	}
}

func makeECDSASignFunc(hash crypto.Hash) ecdsaSignFunc {
	return ecdsaSignFunc(func(payload []byte, key *ecdsa.PrivateKey) ([]byte, error) {
		keysiz := hash.Size()
		curveBits := key.Curve.Params().BitSize
		if curveBits != keysiz*8 {
			return nil, errors.New("key size does not match curve bit size")
		}

		h := hash.New()
		h.Write(payload)
		r, v, err := ecdsa.Sign(rand.Reader, key, h.Sum(nil))
		if err != nil {
			return nil, errors.Wrap(err, "failed to sign payload using ecdsa")
		}
		out := make([]byte, keysiz*2)
		rb := r.Bytes()
		vb := v.Bytes()
		copy(out[keysiz-len(rb):], rb)
		copy(out[keysiz*2-len(vb):], vb)
		return out, nil
	})
}

func newECDSA(alg jwa.SignatureAlgorithm) (*ECDSASigner, error) {
	signfn, ok := ecdsaSignFuncs[alg]
	if !ok {
		return nil, errors.Errorf(`unsupported algorithm while trying to create ECDSA signer: %s`, alg)
	}

	return &ECDSASigner{
		alg: alg,
		sign: signfn,
	}, nil
}

func (s ECDSASigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

func (s ECDSASigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	if key == nil {
		return nil, errors.New(`missing private key while signing payload`)
	}

	ecdsakey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.Errorf(`invalid key type %T. *ecdsa.PrivateKey is required`, key)
	}

	return s.sign(payload, ecdsakey)
}
