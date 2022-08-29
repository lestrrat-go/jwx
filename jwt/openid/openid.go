// Package openid provides a specialized token that provides utilities
// to work with OpenID JWT tokens.
//
// In order to use OpenID claims, you specify the token to use in the
// jwt.Parse method
//
//	jwt.Parse(data, jwt.WithToken(openid.New())
package openid

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var registry = json.NewRegistry()

func (t *stdToken) Clone() (jwt.Token, error) {
	var dst jwt.Token = New()

	for _, pair := range t.makePairs() {
		//nolint:forcetypeassert
		key := pair.Key.(string)
		if err := dst.Set(key, pair.Value); err != nil {
			return nil, fmt.Errorf(`failed to set %s: %w`, key, err)
		}
	}
	return dst, nil
}

// RegisterCustomField allows users to specify that a private field
// be decoded as an instance of the specified type. This option has
// a global effect.
//
// For example, suppose you have a custom field `x-birthday`, which
// you want to represent as a string formatted in RFC3339 in JSON,
// but want it back as `time.Time`.
//
// In that case you would register a custom field as follows
//
//	jwt.RegisterCustomField(`x-birthday`, timeT)
//
// Then `token.Get("x-birthday")` will still return an `interface{}`,
// but you can convert its type to `time.Time`
//
//	bdayif, _ := token.Get(`x-birthday`)
//	bday := bdayif.(time.Time)
func RegisterCustomField(name string, object interface{}) {
	registry.Register(name, object)
}
