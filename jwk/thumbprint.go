package jwk

import (
	"crypto"
	"fmt"
)

// availableHash guards the Thumbprint code paths against an unusable hash.
// crypto.Hash(0) and registered-but-unlinked hashes (e.g. crypto.MD4 without
// importing its package) make hash.New() panic with "requested hash function
// is unavailable"; returning an error instead keeps Thumbprint and its callers
// (such as AssignKeyID) panic-free.
func availableHash(h crypto.Hash) error {
	if !h.Available() {
		return fmt.Errorf(`jwk: thumbprint hash %v is not available (is its package imported?)`, h)
	}
	return nil
}
