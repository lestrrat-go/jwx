package jwe

import "github.com/lestrrat-go/sketch/schema"

var cctype = schema.TypeName(`*cert.Chain`)
var dctype = schema.TypeName(`DecodeCtx`).
	PointerType(`DecodeCtx`)
var jwktype = schema.TypeName(`jwk.Key`).
	InterfaceDecoder(`jwk.ParseKey`).
	IsInterface(true)

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

func (Headers) Fields() []*schema.FieldSpec {
	return []*schema.FieldSpec{
		schema.ByteSlice(`AgreementPartyUInfo`).
			JSON(`apu`),
		schema.ByteSlice(`AgreementPartyVInfo`).
			JSON(`apv`),
		schema.Field(`Algorithm`, schema.TypeName(`jwa.KeyEncryptionAlgorithm`).ZeroVal(`jwa.KeyEncryptionAlgorithm("")`)).
			JSON(`alg`),
		schema.Field(`Compression`, schema.TypeName(`jwa.CompressionAlgorithm`).ZeroVal(`jwa.NoCompress`)).
			JSON(`zip`),
		schema.String(`ContentType`).
			JSON(`cty`),
		schema.Field(`ContentEncryption`, schema.TypeName(`jwa.ContentEncryptionAlgorithm`).ZeroVal(`jwa.ContentEncryptionAlgorithm("")`)).
			JSON(`enc`),
		schema.Field(`Critical`, schema.Type([]string(nil))).
			JSON(`crit`),
		schema.Field(`EphemeralPublicKey`, jwktype).
			JSON(`epk`),
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
