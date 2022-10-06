package jws

import "github.com/lestrrat-go/sketch/schema"

var cctype = schema.TypeName(`*cert.Chain`)
var dctype = schema.TypeName(`DecodeCtx`).
	PointerType(`DecodeCtx`)
var jwktype = schema.TypeName(`jwk.Key`).
	IsInterface(true).
	InterfaceDecoder(`jwk.ParseKey`)

type Headers struct {
	schema.Base
}

func (Headers) Imports() []string {
	return []string{
		"github.com/lestrrat-go/jwx/v2/internal/json",
		"github.com/lestrrat-go/jwx/v2/jwa",
		"github.com/lestrrat-go/jwx/v2/jwk",
	}
}

func (Headers) Name() string {
	return "stdHeaders"
}

func (h Headers) SymbolName(name string) string {
	if name == `object.method.UnmarshalJSON` {
		return `unmarshalJSON`
	}
	return h.Base.SymbolName(name)
}

func (Headers) Fields() []*schema.FieldSpec {
	return []*schema.FieldSpec{
		schema.Field(`Algorithm`, schema.TypeName(`jwa.SignatureAlgorithm`).ZeroVal(`jwa.SignatureAlgorithm("")`)).
			JSON(`alg`),
		schema.String(`ContentType`).
			JSON(`cty`),
		schema.Field(`Critical`, schema.Type([]string(nil))).
			JSON(`crit`),
		schema.Field(`JWK`, jwktype).
			Unexported(`jwk`).
			JSON(`jwk`),
		schema.String(`JWKSetURL`).
			Unexported(`jwkSetURL`).
			JSON(`jku`),
		schema.String(`KeyID`).
			JSON(`kid`),
		schema.String(`Type`).
			Unexported(`typ`),
		schema.Field(`X509CertChain`, cctype).
			Unexported(`x509CertChain`).
			JSON(`x5c`),
		schema.String(`X509CertThumbprint`).
			Unexported(`x509CertThumbprint`).
			JSON(`x5t`),
		schema.String(`X509CertThumbprintS256`).
			Unexported(`x509CertThumbprintS256`).
			JSON(`x5t#S256`),
		schema.String(`X509URL`).
			Unexported(`x509URL`).
			JSON(`x5u`),
		schema.Field(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
		schema.Field(`Raw`, schema.Type([]byte(nil))).
			IsExtension(true),
	}
}
