package jwt

import (
	"time"

	"github.com/lestrrat-go/jwx/internal/option"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

type Option = option.Interface

type parseOption struct {
	Option
}

func newParseOption(n string, v interface{}) ParseOption {
	return &parseOption{Option: option.New(n, v)}
}

func (o *parseOption) isParseOption() bool { return true }

type ParseOption interface {
	Option
	isParseOption() bool
}

type validateOption struct {
	Option
}

func newValidateOption(n string, v interface{}) ValidateOption {
	return &validateOption{Option: option.New(n, v)}
}

func (o *validateOption) isValidateOption() bool { return true }

type ValidateOption interface {
	Option
	isValidateOption() bool
}

const (
	optkeyValidate = `validate`
	optkeyVerify   = `verify`
	optkeyToken    = `token`
	optkeyKeySet   = `keySet`
	optkeyKeyLookup   = `keyLookup`
	optkeyHeaders  = `headers`
	optkeyDefault  = `defaultKey`
	optkeyClaim    = `claimValue`
)

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
	return newParseOption(optkeyVerify, &verifyParams{
		alg: alg,
		key: key,
	})
}

// WithKeySet forces the Parse method to verify the JWT message
// using one of the keys in the given key set. The key to be used
// is chosen by matching the Key ID of the JWT and the ID of the
// give keys.
func WithKeySet(set *jwk.Set) ParseOption {
	return newParseOption(optkeyKeySet, set)
}

// KeyLookupFunc is a hook to lookup the key by kid
type KeyLookupFunc func(kid string) (interface{}, error)

// WithKeyLookup forces the Parse method to verify the JWT message
// using KeyLookupFunc to load the key
func WithKeyLookup(f KeyLookupFunc) ParseOption {
	return newParseOption(optkeyKeyLookup, f)
}

// UseDefaultKey is used in conjunction with the option WithKeySet
// to instruct the Parse method to default to the single key in a key
// set when no Key ID is included in the JWT. If the key set contains
// multiple keys then the behaviour is unchanged.
func UseDefaultKey(value bool) ParseOption {
	return newParseOption(optkeyDefault, value)
}

// WithToken specifies the token instance that is used when parsing
// JWT tokens.
func WithToken(t Token) ParseOption {
	return newParseOption(optkeyToken, t)
}

// WithOpenIDClaims is passed to the various JWT parsing functions, and
// specifies that it should use an instance of `openid.Token` as the
// destination to store the parsed results.
//
// This is exactly equivalent to specifying `jwt.WithToken(openid.New())`
func WithOpenIDClaims() ParseOption {
	return WithToken(openid.New())
}

// WithHeaders is passed to `Sign()` method, to allow specifying arbitrary
// header values to be included in the header section of the jws message
func WithHeaders(hdrs jws.Headers) ParseOption {
	return newParseOption(optkeyHeaders, hdrs)
}

// WithValidate is passed to `Parse()` method to denote that the
// validation of the JWT token should be performed after a successful]
// parsing of the incoming payload.
func WithValidate(b bool) ParseOption {
	return newParseOption(optkeyValidate, b)
}

// WithClock specifies the `Clock` to be used when verifying
// claims exp and nbf.
func WithClock(c Clock) ValidateOption {
	return newValidateOption(optkeyClock, c)
}

// WithAcceptableSkew specifies the duration in which exp and nbf
// claims may differ by. This value should be positive
func WithAcceptableSkew(dur time.Duration) ValidateOption {
	return newValidateOption(optkeyAcceptableSkew, dur)
}

// WithIssuer specifies that expected issuer value. If not specified,
// the value of issuer is not verified at all.
func WithIssuer(s string) ValidateOption {
	return newValidateOption(optkeyIssuer, s)
}

// WithSubject specifies that expected subject value. If not specified,
// the value of subject is not verified at all.
func WithSubject(s string) ValidateOption {
	return newValidateOption(optkeySubject, s)
}

// WithJwtID specifies that expected jti value. If not specified,
// the value of jti is not verified at all.
func WithJwtID(s string) ValidateOption {
	return newValidateOption(optkeyJwtid, s)
}

// WithAudience specifies that expected audience value.
// Verify will return true if one of the values in the `aud` element
// matches this value.  If not specified, the value of issuer is not
// verified at all.
func WithAudience(s string) ValidateOption {
	return newValidateOption(optkeyAudience, s)
}

type claimValue struct {
	name  string
	value interface{}
}

// WithClaimValue specifies that expected any claim value.
func WithClaimValue(name string, v interface{}) ValidateOption {
	return newValidateOption(optkeyClaim, claimValue{name, v})
}
