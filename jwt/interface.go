package jwt

import (
	"errors"
	"time"
)

// NumericDate represents the date format used in the 'nbf' claim
type NumericDate struct {
	time.Time
}

// ErrInvalidValue is returned when an invalid type is passed to
// a known claim (i.e. those defined in EssentialClaims
var ErrInvalidValue = errors.New("invalid value for key")

const numericDateFmt = "2006-01-02T15:04:05Z UTC"

// EssentialClaims contains the set of known set of claims in JWT spec.
type EssentialClaims struct {
	Audience   []string     `json:"aud,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.3
	Expiration int64        `json:"exp,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.4
	IssuedAt   int64        `json:"iat,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.6
	Issuer     string       `json:"iss,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.1
	JwtID      string       `json:"jti,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.7
	NotBefore  *NumericDate `json:"nbf,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.5
	Subject    string       `json:"sub,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.2
}

// ClaimSet holds an arbitrary claim set
type ClaimSet struct {
	*EssentialClaims `json:"-"`
	PrivateClaims    map[string]interface{} `json:"-"`
}
