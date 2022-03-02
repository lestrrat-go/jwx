package jws

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/option"
)

type identHeaders struct{}

// WithHeaders allows you to specify extra header values to include in the
// final JWS message
func WithHeaders(h Headers) SignOption {
	return &signOption{option.New(identHeaders{}, h)}
}

// WithJSON specifies that the result of `jws.Sign()` is serialized in
// JSON format.
//
// If you pass multiple keys to `jws.Sign()`, it will fail unless
// you also pass this option.
func WithJSON(options ...WithJSONSuboption) SignOption {
	var pretty bool
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identPretty{}:
			pretty = option.Value().(bool)
		}
	}

	format := fmtJSON
	if pretty {
		format = fmtJSONPretty
	}
	return &signOption{option.New(identSerialization{}, format)}
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
// When used with `jws.Sign()`, additional suboptions `jws.WithProtected()` and
// `jws.WithPublic()` can be passed to specify JWS headers that should be used whe signing.
// These suboptions are ignored whe the `jws.WithKey()` option is used with `jws.Verify()`.
func WithKey(alg jwa.KeyAlgorithm, key interface{}, options ...WithKeySuboption) SignVerifyOption {
	// Implementation note: this option is shared between Sign() and
	// Verify(). As such we don't create a KeyProvider here because
	// if used in Sign() we would be doing something else.
	var protected, public Headers
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identProtectedHeaders{}:
			protected = option.Value().(Headers)
		case identPublicHeaders{}:
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

func WithKeySet(set jwk.Set, options ...WithKeySetSuboption) VerifyOption {
	var requireKid, useDefault, inferAlgorithm bool
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identRequireKid{}:
			requireKid = option.Value().(bool)
		case identUseDefault{}:
			useDefault = option.Value().(bool)
		case identInferAlgorithmFromKey{}:
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
