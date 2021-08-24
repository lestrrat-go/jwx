package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"io"

	"github.com/lestrrat-go/jwx/internal/keyconv"
	"github.com/lestrrat-go/jwx/internal/pool"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

var ecdsaSigners map[jwa.SignatureAlgorithm]*ecdsaSigner
var ecdsaVerifiers map[jwa.SignatureAlgorithm]*ecdsaVerifier

func init() {
	algs := map[jwa.SignatureAlgorithm]crypto.Hash{
		jwa.ES256:  crypto.SHA256,
		jwa.ES384:  crypto.SHA384,
		jwa.ES512:  crypto.SHA512,
		jwa.ES256K: crypto.SHA256,
	}
	ecdsaSigners = make(map[jwa.SignatureAlgorithm]*ecdsaSigner)
	ecdsaVerifiers = make(map[jwa.SignatureAlgorithm]*ecdsaVerifier)

	for alg, hash := range algs {
		ecdsaSigners[alg] = &ecdsaSigner{
			alg:  alg,
			hash: hash,
		}
		ecdsaVerifiers[alg] = &ecdsaVerifier{
			alg:  alg,
			hash: hash,
		}
	}
}

func newECDSASigner(alg jwa.SignatureAlgorithm) Signer {
	return ecdsaSigners[alg]
}

// ecdsaSigners are immutable.
type ecdsaSigner struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
}

func (s ecdsaSigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

type ecdsaCryptoSigner struct {
	key  *ecdsa.PrivateKey
	hash crypto.Hash
}

func (s *ecdsaSigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	if key == nil {
		return nil, errors.New(`missing private key while signing payload`)
	}

	signer, ok := key.(crypto.Signer)
	if ok {
		// We support crypto.Signer, but we DON'T support
		// ecdsa.PrivateKey as a crypto.Signer, because it encodes
		// the result in ASN1 format.
		if pk, ok := key.(*ecdsa.PrivateKey); ok {
			signer = newECDSACryptoSigner(pk, s.hash)
		}
	} else {
		var privkey ecdsa.PrivateKey
		if err := keyconv.ECDSAPrivateKey(&privkey, key); err != nil {
			return nil, errors.Wrapf(err, `failed to retrieve ecdsa.PrivateKey out of %T`, key)
		}
		signer = newECDSACryptoSigner(&privkey, s.hash)
	}

	h := s.hash.New()
	if _, err := h.Write(payload); err != nil {
		return nil, errors.Wrap(err, "failed to write payload using ecdsa")
	}
	return signer.Sign(rand.Reader, h.Sum(nil), s.hash)
}

func newECDSACryptoSigner(key *ecdsa.PrivateKey, hash crypto.Hash) crypto.Signer {
	return &ecdsaCryptoSigner{
		key:  key,
		hash: hash,
	}
}

func (cs *ecdsaCryptoSigner) Public() crypto.PublicKey {
	return cs.key.PublicKey
}

func (cs *ecdsaCryptoSigner) Sign(seed io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(seed, cs.key, digest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign payload using ecdsa")
	}

	curveBits := cs.key.Curve.Params().BitSize
	keyBytes := curveBits / 8
	// Curve bits do not need to be a multiple of 8.
	if curveBits%8 > 0 {
		keyBytes++
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)
	return out, nil
}

// ecdsaVerifiers are immutable.
type ecdsaVerifier struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
}

func newECDSAVerifier(alg jwa.SignatureAlgorithm) Verifier {
	return ecdsaVerifiers[alg]
}

func (v ecdsaVerifier) Algorithm() jwa.SignatureAlgorithm {
	return v.alg
}

func (v *ecdsaVerifier) Verify(payload []byte, signature []byte, key interface{}) error {
	if key == nil {
		return errors.New(`missing public key while verifying payload`)
	}

	var pubkey ecdsa.PublicKey
	if err := keyconv.ECDSAPublicKey(&pubkey, key); err != nil {
		return errors.Wrapf(err, `failed to retrieve ecdsa.PublicKey out of %T`, key)
	}

	r := pool.GetBigInt()
	s := pool.GetBigInt()
	defer pool.ReleaseBigInt(r)
	defer pool.ReleaseBigInt(s)

	n := len(signature) / 2
	r.SetBytes(signature[:n])
	s.SetBytes(signature[n:])

	h := v.hash.New()
	if _, err := h.Write(payload); err != nil {
		return errors.Wrap(err, "failed to write payload using ecdsa")
	}

	if !ecdsa.Verify(&pubkey, h.Sum(nil), r, s) {
		return errors.New(`failed to verify signature using ecdsa`)
	}
	return nil
}
