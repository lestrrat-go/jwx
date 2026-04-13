// Package openid provides a specialized token that provides utilities
// to work with OpenID JWT tokens.
//
// In order to use OpenID claims, you specify the token to use in the
// jwt.Parse method
//
//	jwt.Parse(data, jwt.WithToken(openid.New())
package openid

import (
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

var registry = json.NewRegistry()

func (t *stdToken) Clone() (jwt.Token, error) {
	dst, _ := New().(*stdToken)
	dst.cloneFrom(t)
	return dst, nil
}

// RegisterCustomField registers a private claim to be decoded as type T
// using json.Unmarshal. This option has a global effect.
//
//	openid.RegisterCustomField[time.Time](`x-birthday`)
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterCustomField[T any](name string) error {
	json.RegisterTyped[T](registry, name)
	return nil
}

// RegisterCustomDecoder registers a private claim with a custom decoder
// function. This option has a global effect.
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterCustomDecoder[T any](name string, dec json.CustomDecodeFunc[T]) error {
	json.RegisterCustomDecoder[T](registry, name, dec)
	return nil
}

// UnregisterCustomField removes the registration for a custom field.
func UnregisterCustomField(name string) {
	registry.Unregister(name)
}
