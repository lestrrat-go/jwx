package jwsbb

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"sync"

	"github.com/lestrrat-go/dsig"
)

type RSAFamilyMeta struct {
	Hash crypto.Hash
	PSS  bool
}

var rsaReverseMap = make(map[RSAFamilyMeta]string)
var muRSAReverseMap sync.RWMutex

func rsaReverseLookup(meta RSAFamilyMeta) (string, bool) {
	muRSAReverseMap.RLock()
	defer muRSAReverseMap.RUnlock()

	alg, ok := rsaReverseMap[meta]
	return alg, ok
}

// SignRSA generates an RSA signature for the given payload using the specified private key and options.
// The raw parameter should be the pre-computed signing input (typically header.payload).
// If pss is true, RSA-PSS is used; otherwise, PKCS#1 v1.5 is used.
//
// The rr parameter is an optional io.Reader that can be used to provide randomness for signing.
// If rr is nil, it defaults to rand.Reader.
func SignRSA(key *rsa.PrivateKey, payload []byte, h crypto.Hash, pss bool, rr io.Reader) ([]byte, error) {
	alg, ok := rsaReverseLookup(RSAFamilyMeta{Hash: h, PSS: pss})
	if !ok {
		return nil, fmt.Errorf(`jwsbb.SignRSA: failed to reserve lookup dsig algorithm name from RSA metadata`)
	}

	return dsig.Sign(key, alg, payload, rr)
}

// VerifyRSA verifies an RSA signature for the given payload and header.
// This function constructs the signing input by encoding the header and payload according to JWS specification,
// then verifies the signature using the specified public key and hash algorithm.
// If pss is true, RSA-PSS verification is used; otherwise, PKCS#1 v1.5 verification is used.
func VerifyRSA(key *rsa.PublicKey, payload, signature []byte, h crypto.Hash, pss bool) error {
	alg, ok := rsaReverseLookup(RSAFamilyMeta{Hash: h, PSS: pss})
	if !ok {
		return fmt.Errorf(`jwsbb.VerifyRSA: failed to reserve lookup dsig algorithm name from RSA metadata`)
	}

	return dsig.Verify(key, alg, payload, signature)
}
