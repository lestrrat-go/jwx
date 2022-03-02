// This file is auto-generated by internal/cmd/genoptions/main.go. DO NOT EDIT

package jwt

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/option"
)

type Option = option.Interface

// EncryptOption describes an Option that can be passed to (jwt.Serializer).Encrypt
type EncryptOption interface {
	Option
	encryptOption()
}

type encryptOption struct {
	Option
}

func (*encryptOption) encryptOption() {}

// GlobalOption describes an Option that can be passed to `Settings()`.
type GlobalOption interface {
	Option
	globalOption()
}

type globalOption struct {
	Option
}

func (*globalOption) globalOption() {}

// ParseOption describes an Option that can be passed to `jwt.Parse()`.
// ParseOption also implements ReadFileOption, therefore it may be
// safely pass them to `jwt.ReadFile()`
type ParseOption interface {
	Option
	parseOption()
	readFileOption()
}

type parseOption struct {
	Option
}

func (*parseOption) parseOption() {}

func (*parseOption) readFileOption() {}

// SignOption describes an Option that can be passed to `jwt.Sign()` or
// (jwt.Serializer).Sign
type SignOption interface {
	Option
	signOption()
}

type signOption struct {
	Option
}

func (*signOption) signOption() {}

// SignParseOption describes an Option that can be passed to both `jwt.Sign()` or
// `jwt.Parse()`
type SignParseOption interface {
	Option
	parseOption()
	readFileOption()
	signOption()
}

type signParseOption struct {
	Option
}

func (*signParseOption) parseOption() {}

func (*signParseOption) readFileOption() {}

func (*signParseOption) signOption() {}

// ValidateOption describes an Option that can be passed to Validate().
// ValidateOption also implements ParseOption, therefore it may be
// safely passed to `Parse()` (and thus `jwt.ReadFile()`)
type ValidateOption interface {
	Option
	parseOption()
	readFileOption()
	validateOption()
}

type validateOption struct {
	Option
}

func (*validateOption) parseOption() {}

func (*validateOption) readFileOption() {}

func (*validateOption) validateOption() {}

type identAcceptableSkew struct{}
type identClock struct{}
type identContext struct{}
type identFlattenAudience struct{}
type identFormKey struct{}
type identHeaderKey struct{}
type identKeyProvider struct{}
type identPedantic struct{}
type identToken struct{}
type identValidate struct{}
type identValidator struct{}

func (identAcceptableSkew) String() string {
	return "WithAcceptableSkew"
}

func (identClock) String() string {
	return "WithClock"
}

func (identContext) String() string {
	return "WithContext"
}

func (identFlattenAudience) String() string {
	return "WithFlattenAudience"
}

func (identFormKey) String() string {
	return "WithFormKey"
}

func (identHeaderKey) String() string {
	return "WithHeaderKey"
}

func (identKeyProvider) String() string {
	return "WithKeyProvider"
}

func (identPedantic) String() string {
	return "WithPedantic"
}

func (identToken) String() string {
	return "WithToken"
}

func (identValidate) String() string {
	return "WithValidate"
}

func (identValidator) String() string {
	return "WithValidator"
}

// WithAcceptableSkew specifies the duration in which exp and nbf
// claims may differ by. This value should be positive
func WithAcceptableSkew(v time.Duration) ValidateOption {
	return &validateOption{option.New(identAcceptableSkew{}, v)}
}

// WithClock specifies the `Clock` to be used when verifying
// exp and nbf claims.
func WithClock(v Clock) ValidateOption {
	return &validateOption{option.New(identClock{}, v)}
}

// WithContext allows you to specify a context.Context object to be used
// with `jwt.Validate()` option.
//
// Please be aware that in the next major release of this library,
// `jwt.Validate()`'s signature will change to include an explicit
// `context.Context` object.
func WithContext(v context.Context) ValidateOption {
	return &validateOption{option.New(identContext{}, v)}
}

// WithFlattenAudience specifies if the "aud" claim should be flattened
// to a single string upon the token being serialized to JSON.
//
// This is sometimes important when a JWT consumer does not understand that
// the "aud" claim can actually take the form of an array of strings.
//
// The default value is `false`, which means that "aud" claims are always
// rendered as a arrays of strings. This setting has a global effect,
// and will change the behavior for all JWT serialization.
func WithFlattenAudience(v bool) GlobalOption {
	return &globalOption{option.New(identFlattenAudience{}, v)}
}

// WithFormKey is used to specify header keys to search for tokens.
//
// While the type system allows this option to be passed to jwt.Parse() directly,
// doing so will have no effect. Only use it for HTTP request parsing functions
func WithFormKey(v string) ParseOption {
	return &parseOption{option.New(identFormKey{}, v)}
}

// WithHeaderKey is used to specify header keys to search for tokens.
//
// While the type system allows this option to be passed to `jwt.Parse()` directly,
// doing so will have no effect. Only use it for HTTP request parsing functions
func WithHeaderKey(v string) ParseOption {
	return &parseOption{option.New(identHeaderKey{}, v)}
}

func WithKeyProvider(v jws.KeyProvider) ParseOption {
	return &parseOption{option.New(identKeyProvider{}, v)}
}

// WithPedantic enables pedantic mode for parsing JWTs. Currently this only
// applies to checking for the correct `typ` and/or `cty` when necessary.
func WithPedantic(v bool) ParseOption {
	return &parseOption{option.New(identPedantic{}, v)}
}

// WithToken specifies the token instance where the result JWT is stored
// when parsing JWT tokensthat is used when parsing
func WithToken(v Token) ParseOption {
	return &parseOption{option.New(identToken{}, v)}
}

// WithValidate is passed to `Parse()` method to denote that the
// validation of the JWT token should be performed after a successful
// parsing of the incoming payload.
func WithValidate(v bool) ParseOption {
	return &parseOption{option.New(identValidate{}, v)}
}

// WithValidator validates the token with the given Validator.
//
// For example, in order to validate tokens that are only valid during August, you would write
//
//    validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) error {
//      if time.Now().Month() != 8 {
//        return fmt.Errorf(`tokens are only valid during August!`)
//      }
//      return nil
//    })
//    err := jwt.Validate(token, jwt.WithValidator(validator))
func WithValidator(v Validator) ValidateOption {
	return &validateOption{option.New(identValidator{}, v)}
}
