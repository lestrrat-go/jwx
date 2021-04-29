package jwt

import (
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/option"
)

type Option = option.Interface

// GlobalOption describes an Option that can be passed to `Settings()`.
type GlobalOption interface {
	Option
	globalOption()
}

type globalOption struct {
	Option
}

func (*globalOption) globalOption() {}

// ParseRequestOption describes an Option that can be passed to `ParseRequest()`.
type ParseRequestOption interface {
	ParseOption
	httpParseOption()
}

type httpParseOption struct {
	ParseOption
}

func (*httpParseOption) httpParseOption() {}

// ParseOption describes an Option that can be passed to `Parse()`.
// ParseOption also implements ReadFileOption, therefore it may be
// safely pass them to `jwt.ReadFile()`
type ParseOption interface {
	ReadFileOption
	parseOption()
}

type parseOption struct {
	Option
}

func newParseOption(n interface{}, v interface{}) ParseOption {
	return &parseOption{option.New(n, v)}
}

func (*parseOption) parseOption()    {}
func (*parseOption) readFileOption() {}

// ValidateOption describes an Option that can be passed to Validate().
// ValidateOption also implements ParseOption, therefore it may be
// safely passed to `Parse()` (and thus `jwt.ReadFile()`)
type ValidateOption interface {
	ParseOption
	validateOption()
}

type validateOption struct {
	ParseOption
}

func newValidateOption(n interface{}, v interface{}) ValidateOption {
	return &validateOption{newParseOption(n, v)}
}

func (*validateOption) validateOption() {}

type identAcceptableSkew struct{}
type identAudience struct{}
type identClaim struct{}
type identClock struct{}
type identDefault struct{}
type identFlattenAudience struct{}
type identHeaders struct{}
type identIssuer struct{}
type identJwtid struct{}
type identKeySet struct{}
type identSubject struct{}
type identToken struct{}
type identValidate struct{}
type identVerify struct{}

type identHeaderKey struct{}
type identFormKey struct{}

type VerifyParameters interface {
	Algorithm() jwa.SignatureAlgorithm
	Key() interface{}
}

type verifyParams struct {
	alg jwa.SignatureAlgorithm
	key interface{}
}

func (p *verifyParams) Algorithm() jwa.SignatureAlgorithm {
	return p.alg
}

func (p *verifyParams) Key() interface{} {
	return p.key
}

// WithVerify forces the Parse method to verify the JWT message
// using the given key. XXX Should have been named something like
// WithVerificationKey
func WithVerify(alg jwa.SignatureAlgorithm, key interface{}) ParseOption {
	return newParseOption(identVerify{}, &verifyParams{
		alg: alg,
		key: key,
	})
}

// WithKeySet forces the Parse method to verify the JWT message
// using one of the keys in the given key set. The key to be used
// is chosen by matching the Key ID of the JWT and the ID of the
// given keys.
//
// When using this option, keys MUST have a properly 'alg' field
// set. This is because we need to know the exact algorithm that
// you (the user) wants to use to verify the token. We do NOT
// trust the token's headers, because they can easily be tampered with.
func WithKeySet(set jwk.Set) ParseOption {
	return newParseOption(identKeySet{}, set)
}

// UseDefaultKey is used in conjunction with the option WithKeySet
// to instruct the Parse method to default to the single key in a key
// set when no Key ID is included in the JWT. If the key set contains
// multiple keys then the behaviour is unchanged.
func UseDefaultKey(value bool) ParseOption {
	return newParseOption(identDefault{}, value)
}

// WithToken specifies the token instance that is used when parsing
// JWT tokens.
func WithToken(t Token) ParseOption {
	return newParseOption(identToken{}, t)
}

// WithHeaders is passed to `Sign()` method, to allow specifying arbitrary
// header values to be included in the header section of the jws message
func WithHeaders(hdrs jws.Headers) ParseOption {
	return newParseOption(identHeaders{}, hdrs)
}

// WithValidate is passed to `Parse()` method to denote that the
// validation of the JWT token should be performed after a successful
// parsing of the incoming payload.
func WithValidate(b bool) ParseOption {
	return newParseOption(identValidate{}, b)
}

// WithClock specifies the `Clock` to be used when verifying
// claims exp and nbf.
func WithClock(c Clock) ValidateOption {
	return newValidateOption(identClock{}, c)
}

// WithAcceptableSkew specifies the duration in which exp and nbf
// claims may differ by. This value should be positive
func WithAcceptableSkew(dur time.Duration) ValidateOption {
	return newValidateOption(identAcceptableSkew{}, dur)
}

// WithIssuer specifies that expected issuer value. If not specified,
// the value of issuer is not verified at all.
func WithIssuer(s string) ValidateOption {
	return newValidateOption(identIssuer{}, s)
}

// WithSubject specifies that expected subject value. If not specified,
// the value of subject is not verified at all.
func WithSubject(s string) ValidateOption {
	return newValidateOption(identSubject{}, s)
}

// WithJwtID specifies that expected jti value. If not specified,
// the value of jti is not verified at all.
func WithJwtID(s string) ValidateOption {
	return newValidateOption(identJwtid{}, s)
}

// WithAudience specifies that expected audience value.
// `Validate()` will return true if one of the values in the `aud` element
// matches this value.  If not specified, the value of issuer is not
// verified at all.
func WithAudience(s string) ValidateOption {
	return newValidateOption(identAudience{}, s)
}

type claimValue struct {
	name  string
	value interface{}
}

// WithClaimValue specifies that expected any claim value.
func WithClaimValue(name string, v interface{}) ValidateOption {
	return newValidateOption(identClaim{}, claimValue{name, v})
}

// WithHeaderKey is used to specify header keys to search for tokens.
//
// While the type system allows this option to be passed to jwt.Parse() directly,
// doing so will have no effect. Only use it for HTTP request parsing functions
func WithHeaderKey(v string) ParseRequestOption {
	return &httpParseOption{newParseOption(identHeaderKey{}, v)}
}

// WithFormKey is used to specify header keys to search for tokens.
//
// While the type system allows this option to be passed to jwt.Parse() directly,
// doing so will have no effect. Only use it for HTTP request parsing functions
func WithFormKey(v string) ParseRequestOption {
	return &httpParseOption{newParseOption(identFormKey{}, v)}
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
