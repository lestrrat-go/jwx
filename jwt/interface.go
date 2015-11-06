package jwt

import "time"

type NumericDate struct {
	time.Time
}

const numericDateFmt = "2006-01-02T15:04:05Z UTC"

type EssentialHeader struct {
	Type        string `json:"typ"`
	ContentType string `json:"cty,omitempty"`
}

type Header struct {
	*EssentialHeader `json:"-"`
	PrivateParams    map[string]interface{} `json:"-"`
}

type EssentialClaims struct {
	Audience   string       `json:"aud,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.3
	Expiration int64        `json:"exp,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.4
	IssuedAt   int64        `json:"iat,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.6
	Issuer     string       `json:"iss,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.1
	JwtID      string       `json:"jtu,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.7
	NotBefore  *NumericDate `json:"nbf,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.5
	Subject    string       `json:"sub,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.2
}

type ClaimSet struct {
	*EssentialClaims `json:"-"`
	PrivateClaims    map[string]interface{} `json:"-"`
}