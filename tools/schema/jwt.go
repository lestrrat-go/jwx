package schema

import (
	"github.com/lestrrat-go/sketch/schema"
)

type JWT struct {
	schema.Base
}

func (JWT) Name() string {
	return "stdToken"
}

func (JWT) Package() string {
	return "jwt"
}

func (JWT) Comment() string {
	return "represents a JWT token"
}

func (JWT) Fields() []*schema.Field {
	ndtyp := schema.Type(`types.NumericDate`).
		ImplementsGet(true).
		UserFacingType(`time.Time`).
		ZeroVal(`nil`)

	return []*schema.Field{
		schema.NewField("Audience", []string{}).
			JSON("aud").
			Comment(`returns the value for "aud" field of the token`),
		schema.NewField("Expiration", ndtyp).
			JSON("exp").
			Comment(`returns the value for "exp" field of the token`),
		schema.NewField("IssuedAt", ndtyp).
			JSON("iat").
			Comment(`returns the value for "iss" field of the token`),
		schema.NewField("NotBefore", ndtyp).
			JSON("nbf").
			Comment(`returns the value for "nbf" field of the token`),
		schema.String("Subject").
			JSON("sub").
			Comment(`returns the value for "sub" field of the token`),
		schema.String("Issuer").
			JSON("iss").
			Comment(`returns the value for "iss" field of the token`),
		schema.String("JwtID").
			JSON("jti").
			Comment(`returns the value for "jti" field of the token`),
	}
}
