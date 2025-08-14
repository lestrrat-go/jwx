package jwsbb

import (
	"fmt"
	"hash"
	"sync"

	"github.com/lestrrat-go/dsig"
)

type HMACFamilyMeta struct {
	Hash hash.Hash
}

var hmacReverseMap = make(map[int]string)
var muHMACReverseMap sync.RWMutex

func hmacReverseLookup(meta int) (string, bool) {
	muHMACReverseMap.RLock()
	defer muHMACReverseMap.RUnlock()

	alg, ok := hmacReverseMap[meta]
	return alg, ok
}

// SignHMAC generates an HMAC signature for the given payload using the specified hash function and key.
// The raw parameter should be the pre-computed signing input (typically header.payload).
func SignHMAC(key, payload []byte, hfunc func() hash.Hash) ([]byte, error) {
	h := hfunc()
	alg, ok := hmacReverseLookup(h.Size())
	if !ok {
		return nil, fmt.Errorf("jwsbb.SignHMAC: unsupported HMAC hash function: size=%d", h.Size())
	}

	// Use dsig.Sign
	return dsig.Sign(key, alg, payload, nil)
}

// VerifyHMAC verifies an HMAC signature for the given payload.
// This function verifies the signature using the specified key and hash function.
// The payload parameter should be the pre-computed signing input (typically header.payload).
func VerifyHMAC(key, payload, signature []byte, hfunc func() hash.Hash) error {
	h := hfunc()
	alg, ok := hmacReverseLookup(h.Size())
	if !ok {
		return fmt.Errorf("jwsbb.VerifyHMAC: unsupported HMAC hash function")
	}

	// Use dsig.Verify
	return dsig.Verify(key, alg, payload, signature)
}
