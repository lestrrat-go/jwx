package jwt

import (
	"github.com/lestrrat-go/jwx/internal/option"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

type Option = option.Interface

const (
	optkeyVerify  = `verify`
	optkeyToken   = `token`
	optkeyKeySet  = `keySet`
	optkeyHeaders = `headers`
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
func WithVerify(alg jwa.SignatureAlgorithm, key interface{}) Option {
	return option.New(optkeyVerify, &verifyParams{
		alg: alg,
		key: key,
	})
}

// WithKeySet forces the Parse method to verify the JWT message
// using one of the keys in the given key set. The key to be used
// is chosen by matching the Key ID of the JWT and the ID of the
// give keys.
func WithKeySet(set *jwk.Set) Option {
	return option.New(optkeyKeySet, set)
}

// WithToken specifies the token instance that is used when parsing
// JWT tokens.
func WithToken(t Token) Option {
	return option.New(optkeyToken, t)
}

// WithOpenIDClaims is passed to the various JWT parsing functions, and
// specifies that it should use an instance of `openid.Token` as the
// destination to store the parsed results.
//
// This is exactly equivalent to specifying `jwt.WithToken(openid.New())`
func WithOpenIDClaims() Option {
	return WithToken(openid.New())
}

// WithHeaders is passed to `Sign()` method, to allow specifying arbitrary
// header values to be included in the header section of the jws message
func WithHeaders(hdrs jws.Headers) Option {
	return option.New(optkeyHeaders, hdrs)
}
