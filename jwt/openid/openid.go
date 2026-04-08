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
func RegisterCustomField[T any](name string) {
	json.RegisterTyped[T](registry, name)
}

// RegisterCustomDecoder registers a private claim with a custom decoder
// function. This option has a global effect.
func RegisterCustomDecoder[T any](name string, dec json.CustomDecodeFunc[T]) {
	json.RegisterCustomDecoder[T](registry, name, dec)
}

// UnregisterCustomField removes the registration for a custom field.
func UnregisterCustomField(name string) {
	registry.Unregister(name)
}
