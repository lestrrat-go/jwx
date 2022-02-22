package jws

import (
	"context"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/option"
)

type Option = option.Interface

type identPayloadSigner struct{}
type identDetachedPayload struct{}
type identHeaders struct{}
type identMessage struct{}

func WithSigner(signer Signer, key interface{}, public, protected Headers) Option {
	return option.New(identPayloadSigner{}, &payloadSigner{
		signer:    signer,
		key:       key,
		protected: protected,
		public:    public,
	})
}

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

type identKeyProvider struct{}
type identRequireKid struct{}
type identUseDefault struct{}
type identInferAlgorithm struct{}
type identKeyUsed struct{}
type identContext struct{}

func WithKey(alg jwa.SignatureAlgorithm, key interface{}) VerifyOption {
	return WithKeyProvider(&staticKeyProvider{
		alg: alg,
		key: key,
	})
}

// WithKeySetOption is an option passed to the WithKeySet() option (recursion!)
type WithKeySetOption interface {
	Option
	withKeySetOption()
}

type withKeySetOption struct {
	Option
}

func (*withKeySetOption) withKeySetOption() {}

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

func WithKeyUsed(v interface{}) VerifyOption {
	return &verifyOption{option.New(identKeyUsed{}, v)}
}

func WithContext(ctx context.Context) VerifyOption {
	return &verifyOption{option.New(identContext{}, ctx)}
}
