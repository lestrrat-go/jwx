package jwt

import "github.com/lestrrat-go/sketch/schema"

var numdatetype = schema.TypeName(`types.NumericDate`).
	GetValue(true).
	AcceptValue(true).
	ApparentType(`time.Time`).
	ZeroVal(`time.Time{}`)
var audtype = schema.TypeName(`types.Audience`).
	PointerType(`types.Audience`).
	GetValue(true).
	AcceptValue(true).
	ApparentType(`[]string`)
var dctype = schema.TypeName(`DecodeCtx`).
	PointerType(`DecodeCtx`)

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

func (JWT) Fields() []*schema.FieldSpec {
	// The comments on these fields are all the sme except for the link...
	commentSrc := func(link string) string {
		return "{{ .GetName }} represents the `{{ .GetJSON }}` field as described in " + link
	}
	return []*schema.FieldSpec{
		schema.Field(`Audience`, audtype).
			JSON(`aud`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.3`)),
		schema.Field(`Expiration`, numdatetype).
			JSON(`exp`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.4`)),
		schema.Field(`IssuedAt`, numdatetype).
			JSON(`iat`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.6`)),
		schema.String(`Issuer`).
			JSON(`iss`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.1`)),
		schema.String(`JwtID`).
			JSON(`jti`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.7`)),
		schema.Field(`NotBefore`, numdatetype).
			JSON(`nbf`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.5`)),
		schema.String(`Subject`).
			JSON(`sub`).
			Comment(commentSrc(`https://tools.ietf.org/html/rfc7519#section-4.1.2`)),
		schema.Field(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
	}
}

type OpenID struct {
	schema.Base
}

func (OpenID) FilenameBase() string {
	return "openid"
}

func (OpenID) Name() string {
	return "stdToken"
}

func (OpenID) BuilderName() string {
	return `Builder`
}

func (OpenID) BuilderResultType() string {
	return `Token`
}

func (OpenID) CloneResultType() string {
	return `Token`
}

func (OpenID) Imports() []string {
	return []string{
		"github.com/lestrrat-go/jwx/v2/jwt/internal/types",
	}
}

func (s OpenID) MethodName(name string) string {
	if name == "builder.method.SetField" {
		return "Claim"
	}
	return s.Base.MethodName(name)
}

func (OpenID) Fields() []*schema.FieldSpec {
	addrtype := schema.TypeName(`*AddressClaim`).
		AcceptValue(true)
	bdtype := schema.TypeName(`*BirthdateClaim`).
		AcceptValue(true)

	return []*schema.FieldSpec{
		schema.Field(`Address`, addrtype),
		schema.Field(`Audience`, audtype).
			JSON(`aud`),
		schema.Field(`Birthdate`, bdtype),
		schema.String(`Email`),
		schema.Bool(`EmailVerified`).
			JSON(`email_verified`),
		schema.Field(`Expiration`, numdatetype).
			JSON(`exp`),
		schema.String(`FamilyName`).
			JSON(`family_name`),
		schema.String(`Gender`),
		schema.String(`GivenName`).
			JSON(`given_name`),
		schema.Field(`IssuedAt`, numdatetype).
			JSON(`iat`),
		schema.String(`Issuer`).
			JSON(`iss`),
		schema.String(`JwtID`).
			JSON(`jti`),
		schema.String(`Locale`),
		schema.String(`MiddleName`).
			JSON(`middle_name`),
		schema.String(`Name`),
		schema.String(`Nickname`),
		schema.Field(`NotBefore`, numdatetype).
			JSON(`nbf`),
		schema.String(`PhoneNumber`).
			JSON(`phone_number`),
		schema.Bool(`PhoneNumberVerified`).
			JSON(`phone_number_verified`),
		schema.String(`Picture`),
		schema.String(`PreferredUsername`).
			JSON(`preferred_username`),
		schema.String(`Profile`),
		schema.String(`Subject`).
			JSON(`sub`),
		schema.Field(`UpdatedAt`, numdatetype).
			JSON(`updated_at`),
		schema.String(`Website`),
		schema.String(`Zoneinfo`),
		schema.Field(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
	}
}
