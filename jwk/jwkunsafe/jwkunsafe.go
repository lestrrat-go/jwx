// Package jwkunsafe provides low-level JWK key construction functions.
//
// This package exposes APIs that are not intended for general use, but are
// necessary for advanced use cases such as external modules that add new key
// types (e.g. Ed448  via github.com/lestrrat-go/jwx-circl-ed448).
//
// Function in this package return objects in incomplete state that end-users
// should not be expected to use directly. For example, the keys returned by
// [NewKey] and [NewPublicKey] have no fields set, and must be fully populated
// by the caller before they can be used. Normally, end-users only receive
// fully-populated keys via [jwk.Parse] and related functions, and never
// need to worry about the objects keys being unusable, which is something
// this module works very hard to ensure.
//
// Unless you know exactly what you are doing, you should not use this package directly.
package jwkunsafe

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/internal/registry"
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
