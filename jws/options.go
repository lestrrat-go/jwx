package jws

import (
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/option"
)

type identHeaders struct{}
type identInsecureNoSignature struct{}

// WithHeaders is deprecated. See WithProtectedHeaders to specify
// headers to include in the jws signature.
//
// Using this option has NO EFFECT.
func WithHeaders(h Headers) SignOption {
	return &signOption{option.New(identHeaders{}, h)}
}

// WithJSON specifies that the result of `jws.Sign()` is serialized in
// JSON format.
//
// If you pass multiple keys to `jws.Sign()`, it will fail unless
// you also pass this option.
func WithJSON(options ...WithJSONSuboption) SignVerifyParseOption {
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
	return &signVerifyParseOption{option.New(identSerialization{}, format)}
}

type withKey struct {
	alg       jwa.KeyAlgorithm
	key       interface{}
	protected Headers
	public    Headers
}

// This exists as an escape hatch to modify the header values after the fact
func (w *withKey) Protected(v Headers) Headers {
	if w.protected == nil && v != nil {
		w.protected = v
	}
	return w.protected
}

// WithKey is used to pass a static algorithm/key pair to either `jws.Sign()` or `jws.Verify()`.
//
// The `alg` parameter is the identifier for the signature algorithm that should be used.
// It is of type `jwa.KeyAlgorithm` but in reality you can only pass `jwa.SignatureAlgorithm`
// types. It is this way so that the value in `(jwk.Key).Algorithm()` can be directly
// passed to the option. If you specify other algorithm types such as `jwa.KeyEncryptionAlgorithm`,
// then you will get an error when `jws.Sign()` or `jws.Verify()` is executed.
//
// The `alg` parameter cannot be "none" (jwa.NoSignature) for security reasons.
// You will have to use a separate, more explicit option to allow the use of "none"
// algorithm (WithInsecureNoSignature).
//
// The algorithm specified in the `alg` parameter MUST be able to support
// the type of key you provided, otherwise an error is returned.
//
// Any of the following is accepted for the `key` parameter:
// * A "raw" key (e.g. rsa.PrivateKey, ecdsa.PrivateKey, etc)
// * A crypto.Signer
// * A jwk.Key
//
// Note that due to technical reasons, this library is NOT able to differentiate
// between a valid/invalid key for given algorithm if the key implements crypto.Signer
// and the key is from an external library. For example, while we can tell that it is
// invalid to use `jwk.WithKey(jwa.RSA256, ecdsaPrivateKey)` because the key is
// presumably from `crypto/ecdsa` or this library, if you use a KMS wrapper
// that implements crypto.Signer that is outside of the go standard library or this
// library, we will not be able to properly catch the misuse of such keys --
// the output will happily generate an ECDSA signature even in the presence of
// `jwa.RSA256`
//
// A `crypto.Signer` is used when the private part of a key is
// kept in an inaccessible location, such as hardware.
// `crypto.Signer` is currently supported for RSA, ECDSA, and EdDSA
// family of algorithms. You may consider using `github.com/jwx-go/crypto-signer`
// if you would like to use keys stored in GCP/AWS KMS services.
//
// If the key is a jwk.Key and the key contains a key ID (`kid` field),
// then it is added to the protected header generated by the signature.
//
// `jws.WithKey()` can further accept suboptions to change signing behavior
// when used with `jws.Sign()`. `jws.WithProtected()` and `jws.WithPublic()`
// can be passed to specify JWS headers that should be used whe signing.
//
// If the protected headers contain "b64" field, then the boolean value for the field
// is respected when serializing. That is, if you specify a header with
// `{"b64": false}`, then the payload is not base64 encoded.
//
// These suboptions are ignored when the `jws.WithKey()` option is used with `jws.Verify()`.
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

// WithKeySet specifies a JWKS (jwk.Set) to use for verification.
//
// Because a JWKS can contain multiple keys and this library cannot tell
// which one of the keys should be used for verification, we by default
// require that both `alg` and `kid` fields in the JWS _and_ the
// key match before a key is considered to be used.
//
// There are ways to override this behavior, but they must be explicitly
// specified by the caller.
//
// To work with keys/JWS messages not having a `kid` field, you may specify
// the suboption `WithKeySetRequired` via `jws.WithKey(key, jws.WithRequireKid(false))`.
// This will allow the library to proceed without having to match the `kid` field.
//
// However, it will still check if the `alg` fields in the JWS message and the key(s)
// match. If you must work with JWS messages that do not have an `alg` field,
// you will need to use `jws.WithKeySet(key, jws.WithInferAlgorithm(true))`.
//
// See the documentation for `WithInferAlgorithm()` for more details.
func WithKeySet(set jwk.Set, options ...WithKeySetSuboption) VerifyOption {
	requireKid := true
	var useDefault, inferAlgorithm, multipleKeysPerKeyID bool
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identRequireKid{}:
			requireKid = option.Value().(bool)
		case identUseDefault{}:
			useDefault = option.Value().(bool)
		case identMultipleKeysPerKeyID{}:
			multipleKeysPerKeyID = option.Value().(bool)
		case identInferAlgorithmFromKey{}:
			inferAlgorithm = option.Value().(bool)
		}
	}

	return WithKeyProvider(&keySetProvider{
		set:                  set,
		requireKid:           requireKid,
		useDefault:           useDefault,
		multipleKeysPerKeyID: multipleKeysPerKeyID,
		inferAlgorithm:       inferAlgorithm,
	})
}

func WithVerifyAuto(f jwk.Fetcher, options ...jwk.FetchOption) VerifyOption {
	if f == nil {
		f = jwk.FetchFunc(jwk.Fetch)
	}

	// the option MUST start with a "disallow no whitelist" to force
	// users provide a whitelist
	options = append(append([]jwk.FetchOption(nil), jwk.WithFetchWhitelist(allowNoneWhitelist)), options...)

	return WithKeyProvider(jkuProvider{
		fetcher: f,
		options: options,
	})
}

type withInsecureNoSignature struct {
	protected Headers
}

// This exists as an escape hatch to modify the header values after the fact
func (w *withInsecureNoSignature) Protected(v Headers) Headers {
	if w.protected == nil && v != nil {
		w.protected = v
	}
	return w.protected
}

// WithInsecureNoSignature creates an option that allows the user to use the
// "none" signature algorithm.
//
// Please note that this is insecure, and should never be used in production
// (this is exactly why specifying "none"/jwa.NoSignature to `jws.WithKey()`
// results in an error when `jws.Sign()` is called -- we do not allow using
// "none" by accident)
//
// TODO: create specific suboption set for this option
func WithInsecureNoSignature(options ...WithKeySuboption) SignOption {
	var protected Headers
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identProtectedHeaders{}:
			protected = option.Value().(Headers)
		}
	}

	return &signOption{
		option.New(identInsecureNoSignature{},
			&withInsecureNoSignature{
				protected: protected,
			},
		),
	}
}
