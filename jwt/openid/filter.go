package openid

import (
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// StandardClaimsFilter returns a TokenFilter that filters out standard OpenID claims.
//
// You can use this filter to create tokens that either only has standard OpenID claims
// or only custom claims. If you need to configure the filter more precisely, consider
// using the jwt.ClaimNameFilter directly.
func StandardClaimsFilter() jwt.TokenFilter {
	return stdClaimsFilter
}

var stdClaimsFilter = jwt.NewClaimNameFilter(stdClaimNames...)
