package jwkschema

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"regexp"
	"strings"

	"github.com/lestrrat-go/sketch/schema"
)

type keyBase struct{}

// Each type hides behind an interface
func (keyBase) InterfaceName() string { return "" }

// Each key has a corresponding native key type, such as rsa.PrivateKey
func (keyBase) NativeKeyType() *schema.TypeSpec { return nil }

func (keyBase) KeyType() string {
	return ""
}

var commonImports = []string{
	"github.com/lestrrat-go/jwx/v2/internal/json",
	"github.com/lestrrat-go/jwx/v2/jwa",
}

var cctype = schema.TypeName(`*cert.Chain`)
var dctype = schema.TypeName(`DecodeCtx`).
	PointerType(`DecodeCtx`)
var algtype = schema.TypeName(`jwa.KeyAlgorithm`).
	IsInterface(true).
	AcceptValueMethodName("jwa.KeyAlgorithmFrom").
	ZeroVal(`jwa.UnknownKeyAlgorithm("")`)

var ecatype = schema.TypeName(`jwa.EllipticCurveAlgorithm`).
	AcceptValueMethodName(`Accept`).
	ZeroVal(`jwa.EllipticCurveAlgorithm("")`)
var kttype = schema.TypeName(`jwa.KeyType`).
	AcceptValueMethodName("Accept")
var kutype = schema.TypeName(`KeyUsageType`).
	GetValueMethodName("Get").
	AcceptValueMethodName("Accept").
	ApparentType("string").
	ZeroVal(`""`)

func commonFields(kty string) []*schema.FieldSpec {
	keyoptype := schema.TypeName(`KeyOperationList`)
	return []*schema.FieldSpec{
		schema.Field(`Algorithm`, algtype).
			Extra(`Common`, true).
			JSON(`alg`),
		schema.String(`KeyID`).
			Extra(`common`, true).
			JSON(`kid`),
		schema.Field(`KeyOps`, keyoptype).
			Extra(`common`, true).
			JSON(`key_ops`),
		schema.Field(`KeyType`, kttype).
			ConstantValue(kty).
			Extra(`common`, true).
			JSON(`kty`),
		schema.Field(`KeyUsage`, kutype).
			Extra(`common`, true).
			JSON(`use`),
		schema.Field(`X509CertChain`, cctype).
			Unexported(`x509CertChain`).
			Extra(`common`, true).
			JSON(`x5c`),
		schema.String(`X509CertThumbprint`).
			Unexported(`x509CertThumbprint`).
			Extra(`common`, true).
			JSON(`x5t`),
		schema.String(`X509CertThumbprintS256`).
			Unexported(`x509CertThumbprintS256`).
			Extra(`common`, true).
			JSON(`x5t#S256`),
		schema.String(`X509URL`).
			Unexported(`x509URL`).
			Extra(`common`, true).
			JSON(`x5u`),
	}
}

var commonConstants []*regexp.Regexp

func init() {
	for _, field := range commonFields("dummy") {
		rx := regexp.MustCompile(`^object\.const\..*` + field.GetName() + `Key$`)
		commonConstants = append(commonConstants, rx)
	}
}

func commonKeyName(object schema.Interface, fieldName string) string {
	for _, field := range commonFields("dummy") {
		if field.GetName() == fieldName {
			return fieldName + `Key`
		}
	}
	return object.KeyNamePrefix() + fieldName + `Key`
}

type RSAPrivateKey struct {
	schema.Base
	keyBase
}

func (RSAPrivateKey) Name() string {
	return "rsaPrivateKey"
}

func (RSAPrivateKey) KeyType() string {
	return "jwa.RSA"
}

func (RSAPrivateKey) Imports() []string {
	return commonImports
}

func (RSAPrivateKey) NativeKeyType() *schema.TypeSpec {
	return schema.Type(rsa.PrivateKey{})
}

func (RSAPrivateKey) InterfaceName() string {
	return "RSAPrivateKey"
}

func (RSAPrivateKey) KeyNamePrefix() string {
	return "RSA"
}

func (schema RSAPrivateKey) GetKeyName(s string) string {
	return commonKeyName(schema, s)
}

func (schema RSAPrivateKey) GenerateSymbol(name string) bool {
	for _, rx := range commonConstants {
		if rx.MatchString(name) {
			return false
		}
	}
	if strings.HasPrefix(name, `builder.`) {
		return false
	}
	return schema.Base.GenerateSymbol(name)
}

func (RSAPrivateKey) Fields() []*schema.FieldSpec {
	return append(commonFields("jwa.RSA"), []*schema.FieldSpec{
		schema.ByteSlice(`D`),
		schema.ByteSlice(`DP`).
			Comment(`{{ .GetName }} returns the value of d mod p - 1`),
		schema.ByteSlice(`DQ`).
			Comment(`{{ .GetName }} returns the value of d mod q - 1`),
		schema.ByteSlice(`E`).
			Required(true),
		schema.ByteSlice(`N`).
			Required(true),
		schema.ByteSlice(`P`),
		schema.ByteSlice(`Q`),
		schema.ByteSlice(`QI`).
			Comment(`{{ .GetName }} returns the value of q**-1 mod p`),
		schema.Field(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
	}...)
}

type RSAPublicKey struct {
	schema.Base
	keyBase
}

func (RSAPublicKey) Name() string {
	return "rsaPublicKey"
}

func (RSAPublicKey) KeyType() string {
	return "jwa.RSA"
}

func (RSAPublicKey) Imports() []string {
	return commonImports
}

func (RSAPublicKey) NativeKeyType() *schema.TypeSpec {
	return schema.Type(rsa.PublicKey{})
}

func (RSAPublicKey) InterfaceName() string {
	return "RSAPublicKey"
}

func (RSAPublicKey) KeyNamePrefix() string {
	return "RSA"
}

func (schema RSAPublicKey) GetKeyName(s string) string {
	return commonKeyName(schema, s)
}

func (schema RSAPublicKey) GenerateSymbol(name string) bool {
	if strings.HasPrefix(name, `object.const.`) || strings.HasPrefix(name, `builder.`) {
		return false
	}
	return schema.Base.GenerateSymbol(name)
}

func (RSAPublicKey) Fields() []*schema.FieldSpec {
	return append(commonFields("jwa.RSA"), []*schema.FieldSpec{
		schema.ByteSlice(`E`).
			Required(true),
		schema.ByteSlice(`N`).
			Required(true),
		schema.Field(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
	}...)
}

type ECDSAPrivateKey struct {
	schema.Base
	keyBase
}

func (ECDSAPrivateKey) Name() string {
	return "ecdsaPrivateKey"
}

func (ECDSAPrivateKey) KeyType() string {
	return "jwa.EC"
}

func (ECDSAPrivateKey) Imports() []string {
	return commonImports
}

func (ECDSAPrivateKey) InterfaceName() string {
	return "ECDSAPrivateKey"
}

func (ECDSAPrivateKey) NativeKeyType() *schema.TypeSpec {
	return schema.Type(ecdsa.PrivateKey{})
}

func (ECDSAPrivateKey) KeyNamePrefix() string {
	return "ECDSA"
}

func (schema ECDSAPrivateKey) GetKeyName(s string) string {
	return commonKeyName(schema, s)
}

func (schema ECDSAPrivateKey) GenerateSymbol(name string) bool {
	for _, rx := range commonConstants {
		if rx.MatchString(name) {
			return false
		}
	}
	if strings.HasPrefix(name, `builder.`) {
		return false
	}
	return schema.Base.GenerateSymbol(name)
}

func (ECDSAPrivateKey) Fields() []*schema.FieldSpec {
	return append(commonFields("jwa.EC"), []*schema.FieldSpec{
		schema.Field(`Crv`, ecatype).
			Required(true),
		schema.ByteSlice(`D`).
			Required(true),
		schema.ByteSlice(`X`).
			Required(true),
		schema.ByteSlice(`Y`).
			Required(true),
		schema.Field(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
	}...)
}

type ECDSAPublicKey struct {
	schema.Base
	keyBase
}

func (ECDSAPublicKey) Name() string {
	return "ecdsaPublicKey"
}

func (ECDSAPublicKey) KeyType() string {
	return "jwa.EC"
}

func (ECDSAPublicKey) Imports() []string {
	return commonImports
}

func (ECDSAPublicKey) InterfaceName() string {
	return "ECDSAPublicKey"
}

func (ECDSAPublicKey) NativeKeyType() *schema.TypeSpec {
	return schema.Type(ecdsa.PublicKey{})
}

func (ECDSAPublicKey) KeyNamePrefix() string {
	return "ECDSA"
}

func (schema ECDSAPublicKey) GetKeyName(fieldName string) string {
	return commonKeyName(schema, fieldName)
}

func (schema ECDSAPublicKey) GenerateSymbol(name string) bool {
	if strings.HasPrefix(name, `object.const.`) || strings.HasPrefix(name, `builder.`) {
		return false
	}

	return schema.Base.GenerateSymbol(name)
}

func (ECDSAPublicKey) Fields() []*schema.FieldSpec {
	return append(commonFields("jwa.EC"), []*schema.FieldSpec{
		schema.Field(`Crv`, ecatype).
			Required(true),
		schema.ByteSlice(`X`).
			Required(true),
		schema.ByteSlice(`Y`).
			Required(true),
		schema.Field(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
	}...)
}

type OKPPrivateKey struct {
	schema.Base
	keyBase
}

func (OKPPrivateKey) Name() string {
	return "okpPrivateKey"
}

func (OKPPrivateKey) KeyType() string {
	return "jwa.OKP"
}

func (OKPPrivateKey) Imports() []string {
	return commonImports
}

func (OKPPrivateKey) InterfaceName() string {
	return "OKPPrivateKey"
}

func (OKPPrivateKey) NativeKeyType() *schema.TypeSpec {
	return schema.TypeName(`interface{}`).
		PointerType(`interface{}`)
}

func (OKPPrivateKey) KeyNamePrefix() string {
	return "OKP"
}

func (schema OKPPrivateKey) GetKeyName(s string) string {
	return commonKeyName(schema, s)
}

func (schema OKPPrivateKey) GenerateSymbol(name string) bool {
	for _, rx := range commonConstants {
		if rx.MatchString(name) {
			return false
		}
	}
	if strings.HasPrefix(name, `builder.`) {
		return false
	}
	return schema.Base.GenerateSymbol(name)
}

func (OKPPrivateKey) Fields() []*schema.FieldSpec {
	return append(commonFields("jwa.OKP"), []*schema.FieldSpec{
		schema.Field(`Crv`, ecatype).
			Required(true),
		schema.ByteSlice(`D`).
			Required(true),
		schema.ByteSlice(`X`).
			Required(true),
		schema.Field(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
	}...)
}

type OKPPublicKey struct {
	schema.Base
	keyBase
}

func (OKPPublicKey) Name() string {
	return "okpPublicKey"
}

func (OKPPublicKey) KeyType() string {
	return "jwa.OKP"
}

func (OKPPublicKey) Imports() []string {
	return commonImports
}

func (OKPPublicKey) InterfaceName() string {
	return "OKPPublicKey"
}

func (OKPPublicKey) KeyNamePrefix() string {
	return "OKP"
}

func (OKPPublicKey) NativeKeyType() *schema.TypeSpec {
	return schema.TypeName(`interface{}`).
		PointerType(`interface{}`)
}

func (schema OKPPublicKey) GetKeyName(s string) string {
	return commonKeyName(schema, s)
}

func (schema OKPPublicKey) GenerateSymbol(name string) bool {
	if strings.HasPrefix(name, `object.const.`) || strings.HasPrefix(name, `builder.`) {
		return false
	}

	return schema.Base.GenerateSymbol(name)
}

func (OKPPublicKey) Fields() []*schema.FieldSpec {
	return append(commonFields("jwa.OKP"), []*schema.FieldSpec{
		schema.Field(`Crv`, ecatype).
			Required(true),
		schema.ByteSlice(`X`).
			Required(true),
		schema.Field(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
	}...)
}

type SymmetricKey struct {
	schema.Base
	keyBase
}

func (SymmetricKey) Name() string {
	return "symmetricKey"
}

func (SymmetricKey) KeyType() string {
	return "jwa.OctetSeq"
}

func (SymmetricKey) Imports() []string {
	return commonImports
}

func (SymmetricKey) InterfaceName() string {
	return "SymmetricKey"
}

func (SymmetricKey) NativeKeyType() *schema.TypeSpec {
	return schema.NativeByteSliceType
}

func (SymmetricKey) KeyNamePrefix() string {
	return "Symmetric"
}

func (schema SymmetricKey) GetKeyName(s string) string {
	return commonKeyName(schema, s)
}

func (schema SymmetricKey) GenerateSymbol(name string) bool {
	for _, rx := range commonConstants {
		if rx.MatchString(name) {
			return false
		}
	}
	if strings.HasPrefix(name, `builder.`) {
		return false
	}
	return schema.Base.GenerateSymbol(name)
}

func (SymmetricKey) Fields() []*schema.FieldSpec {
	return append(commonFields("jwa.OctetSeq"), []*schema.FieldSpec{
		schema.ByteSlice(`Octets`).
			JSON(`k`).
			Required(true),
		schema.Field(`DecodeCtx`, dctype).
			Unexported(`dc`).
			IsExtension(true),
	}...)
}
