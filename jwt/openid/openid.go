// Package openid provides a specialized token that provides utilities
// to work with OpenID JWT tokens.
//
// In order to use OpenID claims, you specify the token to use in the
// jwt.Parse method
//
//    jwt.Parse(data, jwt.WithOpenIDClaims())
package openid

import (
	"context"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
)

func (t *stdToken) Clone() (jwt.Token, error) {
	var dst jwt.Token = New()

	ctx := context.Background()
	for iter := t.Iterate(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		if err := dst.Set(pair.Key.(string), pair.Value); err != nil {
			return nil, errors.Wrapf(err, `failed to set %s`, pair.Key.(string))
		}
	}
	return dst, nil
}
