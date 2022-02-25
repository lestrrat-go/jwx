package jws

import (
	"context"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/option"
)

type Option = option.Interface

type identContext struct{}
type identDetachedPayload struct{}
type identMessage struct{}
type identHeaders struct{}
type identKey struct{}
type identKeyUsed struct{}
type identKeyProvider struct{}
type identSerialization struct{}

// WithKey options
type identSignProtected struct{}
type identSignPublic struct{}

// WithKeySet options
type identRequireKid struct{}
type identUseDefault struct{}
type identInferAlgorithm struct{}

type SignOption interface {
	Option
	signOption()
}

type signOption struct {
	Option
}

func (*signOption) signOption() {}

// WithHeaders allows you to specify extra header values to include in the
// final JWS message
func WithHeaders(h Headers) SignOption {
	return &signOption{option.New(identHeaders{}, h)}
}

// VerifyOption describes an option that can be passed to the jws.Verify function
type VerifyOption interface {
	Option
	verifyOption()
}

type verifyOption struct {
	Option
}

func (*verifyOption) verifyOption() {}

// WithMessage can be passed to Verify() to obtain the jws.Message upon
// a successful verification.
func WithMessage(m *Message) VerifyOption {
	return &verifyOption{option.New(identMessage{}, m)}
}

type SignVerifyOption interface {
	SignOption
	VerifyOption
}

type signVerifyOption struct {
	Option
}

func (*signVerifyOption) signOption()   {}
func (*signVerifyOption) verifyOption() {}

// WithDetachedPayload can be used to both sign or verify a JWS message with a
// detached payload.
//
// When this option is used for `jws.Sign()`, the first parameter (normally the payload)
// must be set to `nil`.
//
// If you have to verify using this option, you should know exactly how and why this works.
func WithDetachedPayload(v []byte) SignVerifyOption {
	return &signVerifyOption{option.New(identDetachedPayload{}, v)}
}

// WithCompact specifies that the result of `jws.Sign()` is serialized in
// compact format.
//
// By default `jws.Sign()` will opt to use compact format, so you usually
// do not need to specify this option other than to be explicit about it
func WithCompact() SignOption {
	return &signOption{option.New(identSerialization{}, fmtCompact)}
}

// WithJSON specifies that the result of `jws.Sign()` is serialized in
// JSON format.
//
// If you pass multiple keys to `jws.Sign()`, it will fail unless
// you also pass this option.
func WithJSON() SignOption {
	return &signOption{option.New(identSerialization{}, fmtJSON)}
}

// WithKeyOption describes option types that can be passed to the `jws.WithKey()`
// option.
type WithKeyOption interface {
	Option
	withKeyOption()
}

type withKeyOption struct {
	Option
}

func (*withKeyOption) withKeyOption() {}

// WithProtected is used with `jws.WithKey()` option when used with `jws.Sign()`
// to specify a protected header to be attached to the JWS signature.
//
// It has no effect if used when `jws.WithKey()` is passed to `jws.Verify()`
func WithProtected(hdr Headers) WithKeyOption {
	return &withKeyOption{option.New(identSignProtected{}, hdr)}
}

// WithPublic is used with `jws.WithKey()` option when used with `jws.Sign()`
// to specify a public header to be attached to the JWS signature.
//
// It has no effect if used when `jws.WithKey()` is passed to `jws.Verify()`
//
// `jws.Sign()` will result in an error if `jws.WithPublic()` is used
// and the serialization format is compact serialization.
func WithPublic(hdr Headers) WithKeyOption {
	return &withKeyOption{option.New(identSignPublic{}, hdr)}
}

type withKey struct {
	alg       jwa.KeyAlgorithm
	key       interface{}
	protected Headers
	public    Headers
}

// This exist as escape hatches to modify the header values after the fact
func (w *withKey) Protected(v Headers) Headers {
	if w.protected == nil && v != nil {
		w.protected = v
	}
	return w.protected
}

// WithKey is used to pass algorithm/key pair to either `jws.Sign()` or `jws.Verify()`.
//
// When used with `jws.Sign()`, additional properties `jws.WithProtected()` and
// `jws.WithPublic()` to specify JWS headers that should be used whe signing().
// These options are ignored whe the `jws.WithKey()` option is used with `jws.Verify()`.
func WithKey(alg jwa.KeyAlgorithm, key interface{}, options ...WithKeyOption) SignVerifyOption {
	// Implementation note: this option is shared between Sign() and
	// Verify(). As such we don't create a KeyProvider here because
	// if used in Sign() we would be doing something else.
	var protected, public Headers
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identSignProtected{}:
			protected = option.Value().(Headers)
		case identSignPublic{}:
			public = option.Value().(Headers)
		}
	}

	return &signVerifyOption{
		option.New(identKey{}, &withKey{
			alg:       alg,
			key:       key,
			protected: protected,
			public:    public,
		}),
	}
}

// WithKeySetOption is a suboption passed to the WithKeySet() option
type WithKeySetOption interface {
	Option
	withKeySetOption()
}

type withKeySetOption struct {
	Option
}

func (*withKeySetOption) withKeySetOption() {}

// WithrequiredKid specifies whether the keys in the jwk.Set should
// only be matched if the target JWS message's Key ID and the Key ID
// in the given key matches.
func WithRequireKid(v bool) WithKeySetOption {
	return &withKeySetOption{option.New(identRequireKid{}, v)}
}

func WithUseDefault(v bool) WithKeySetOption {
	return &withKeySetOption{option.New(identUseDefault{}, v)}
}

func WithInferAlgorithmFromKey(v bool) WithKeySetOption {
	return &withKeySetOption{option.New(identInferAlgorithm{}, v)}
}

func WithKeySet(set jwk.Set, options ...WithKeySetOption) VerifyOption {
	var requireKid, useDefault, inferAlgorithm bool
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identRequireKid{}:
			requireKid = option.Value().(bool)
		case identUseDefault{}:
			useDefault = option.Value().(bool)
		case identInferAlgorithm{}:
			inferAlgorithm = option.Value().(bool)
		}
	}

	return WithKeyProvider(&keySetProvider{
		set:            set,
		requireKid:     requireKid,
		useDefault:     useDefault,
		inferAlgorithm: inferAlgorithm,
	})
}

func WithVerifyAuto(f jwk.SetFetcher, options ...jwk.FetchOption) VerifyOption {
	if f == nil {
		f = jwk.SetFetchFunc(jwk.Fetch)
	}

	// the option MUST start with a "disallow no whitelist" to force
	// users provide a whitelist
	options = append(append([]jwk.FetchOption(nil), jwk.WithFetchWhitelist(allowNoneWhitelist)), options...)

	return WithKeyProvider(jkuProvider{
		fetcher: f,
		options: options,
	})
}

func WithKeyProvider(kp KeyProvider) VerifyOption {
	return &verifyOption{option.New(identKeyProvider{}, kp)}
}

// WithKeyUsed allows you to specify the `jws.Verify()` function to
// return the key used for verification. This may be useful when
// you specify multiple key sources or if you pass a `jwk.Set`
// and you want to know which key was successful at verifying the
// signature.
//
// `v` must be a pointer to an empty `interface{}`. Do not use
// `jwk.Key` here unless you are 100% sure that all keys that you
// have provided are instances of `jwk.Key` (remember that the
// jwx API allows users to specify a raw key such as *rsa.PublicKey)
func WithKeyUsed(v interface{}) VerifyOption {
	return &verifyOption{option.New(identKeyUsed{}, v)}
}

func WithContext(ctx context.Context) VerifyOption {
	return &verifyOption{option.New(identContext{}, ctx)}
}
