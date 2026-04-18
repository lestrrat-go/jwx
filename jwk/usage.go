package jwk

import (
	"fmt"
	"sync"
	"sync/atomic"
)

var strictKeyUsage = atomic.Bool{}
var keyUsageNames = map[string]struct{}{}
var muKeyUsageName sync.RWMutex

// RegisterKeyUsage registers a possible value that can be used for KeyUsageType.
// Normally, key usage (or the "use" field in a JWK) is either "sig" or "enc",
// but other values may be used.
//
// While this module only works with "sig" and "enc", it is possible that
// systems choose to use other values. This function allows users to register
// new values to be accepted as valid key usage types. Values are case sensitive.
//
// Furthermore, the check against registered values can be completely turned off
// by setting the global option `jwk.WithStrictKeyUsage(false)`.
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterKeyUsage(v string) error {
	muKeyUsageName.Lock()
	defer muKeyUsageName.Unlock()
	keyUsageNames[v] = struct{}{}
	return nil
}

// UnregisterKeyUsage removes v from the allowlist maintained by
// [RegisterKeyUsage]. The error return is reserved for future
// validation (for example, refusing to unregister a built-in usage
// value like "sig" or "enc") and is always nil today. Callers
// scripting Register/Unregister cycles should check the returned
// value and propagate on failure to stay forward-compatible,
// matching the convention on [RegisterKeyUsage].
func UnregisterKeyUsage(v string) error {
	muKeyUsageName.Lock()
	defer muKeyUsageName.Unlock()
	delete(keyUsageNames, v)
	return nil
}

func init() {
	strictKeyUsage.Store(true)
	if err := RegisterKeyUsage("sig"); err != nil {
		panic(fmt.Sprintf("jwk: failed to register builtin KeyUsage: %s", err))
	}
	if err := RegisterKeyUsage("enc"); err != nil {
		panic(fmt.Sprintf("jwk: failed to register builtin KeyUsage: %s", err))
	}
}

func isValidUsage(v string) bool {
	// This function can return true if strictKeyUsage is false
	if !strictKeyUsage.Load() {
		return true
	}

	muKeyUsageName.RLock()
	defer muKeyUsageName.RUnlock()
	_, ok := keyUsageNames[v]
	return ok
}

func (k KeyUsageType) String() string {
	return string(k)
}

func (k *KeyUsageType) Accept(v any) error {
	switch v := v.(type) {
	case KeyUsageType:
		if !isValidUsage(v.String()) {
			return fmt.Errorf("invalid key usage type: %q", v)
		}
		*k = v
		return nil
	case string:
		if !isValidUsage(v) {
			return fmt.Errorf("invalid key usage type: %q", v)
		}
		*k = KeyUsageType(v)
		return nil
	}

	return fmt.Errorf("invalid Go type for key usage type: %T", v)
}
