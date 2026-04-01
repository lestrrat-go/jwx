// Package jwkunsafe provides low-level JWK key construction functions.
//
// These functions create empty, unpopulated key objects. In most cases you
// should use [jwk.Import] or [jwk.ParseKey] instead. This package exists
// for extension module authors who need to register custom [jwk.KeyImporter]
// implementations for new key types (e.g. Ed448).
package jwkunsafe

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwk/internal/registry"
)

// NewKey creates a new empty private (or symmetric) key for the given key type.
// The returned key has no fields set — the caller must populate it via
// [jwk.Key.Set] before use.
func NewKey(kty jwa.KeyType) (jwk.Key, error) {
	v, err := registry.NewKey(kty.String())
	if err != nil {
		return nil, fmt.Errorf(`jwkunsafe.NewKey: %w`, err)
	}
	key, ok := v.(jwk.Key)
	if !ok {
		return nil, fmt.Errorf(`jwkunsafe.NewKey: internal error: constructor for %q returned %T, not jwk.Key`, kty, v)
	}
	return key, nil
}

// NewPublicKey creates a new empty public key for the given key type.
// Returns an error for key types that have no public/private distinction
// (e.g. symmetric keys). The returned key has no fields set — the caller
// must populate it via [jwk.Key.Set] before use.
func NewPublicKey(kty jwa.KeyType) (jwk.Key, error) {
	v, err := registry.NewPublicKey(kty.String())
	if err != nil {
		return nil, fmt.Errorf(`jwkunsafe.NewPublicKey: %w`, err)
	}
	key, ok := v.(jwk.Key)
	if !ok {
		return nil, fmt.Errorf(`jwkunsafe.NewPublicKey: internal error: constructor for %q returned %T, not jwk.Key`, kty, v)
	}
	return key, nil
}
