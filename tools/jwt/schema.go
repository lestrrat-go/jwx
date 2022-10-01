package jwt

import "github.com/lestrrat-go/sketch/schema"

type JWT struct {
	schema.Base
}

func (JWT) Name() string {
	return "stdToken"
}

func (JWT) BuilderName() string {
	return `Builder`
}

func (JWT) BuilderResultType() string {
	return `Token`
}

func (JWT) CloneResultType() string {
	return `Token`
}

func (JWT) Imports() []string {
	return []string{
		"github.com/lestrrat-go/jwx/v2/jwt/internal/types",
	}
}

func (s JWT) MethodName(name string) string {
	if name == "builder.method.SetField" {
		return "Claim"
	}
	return s.Base.MethodName(name)
}

func (JWT) Fields() []*schema.Field {
	numdatetype := schema.Type(`types.NumericDate`).
		ImplementsGet(true).
		ImplementsAccept(true).
		ApparentType(`time.Time`).
		ZeroVal(`time.Time{}`)
	audtype := schema.Type(`types.Audience`).
		IndirectType(`types.Audience`).
		ImplementsGet(true).
		ImplementsAccept(true).
		ApparentType(`[]string`)

	dctype := schema.Type(`DecodeCtx`).
		IndirectType(`DecodeCtx`)

	// The comments on these fields are all the sme except for the link...
	commentSrc := func(link string) string {
		return "{{ .GetName }} represents the `{{ .GetJSON }}` field as described in " + link
	}
	return []*schema.Field{
		schema.NewField(`Audience`, audtype).
			JSON(`aud`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.3`)),
		schema.NewField(`Expiration`, numdatetype).
			JSON(`exp`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.4`)),
		schema.NewField(`IssuedAt`, numdatetype).
			JSON(`iat`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.6`)),
		schema.String(`Issuer`).
			JSON(`iss`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.1`)),
		schema.String(`JwtID`).
			JSON(`jti`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.7`)),
		schema.NewField(`NotBefore`, numdatetype).
			JSON(`nbf`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.5`)),
		schema.String(`Subject`).
			JSON(`sub`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.2`)),
		schema.NewField(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
	}
}
