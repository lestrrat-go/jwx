package jwt

import (
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/option"
)

type identDecrypt struct{}
type identDefault struct{}
type identInferAlgorithmFromKey struct{}
type identJweHeaders struct{}
type identKey struct{}
type identKeySet struct{}
type identTypedClaim struct{}
type identVerifyAuto struct{}

// WithKey forces the Parse method to verify the JWT message
// using the given key.
//
// This is a utility wrapper around `jws.WithKey()`
func WithKey(alg jwa.KeyAlgorithm, key interface{}, options ...jws.WithKeySuboption) SignParseOption {
	return &signParseOption{option.New(identKey{}, jws.WithKey(alg, key, options...))}
}

// WithKeySet forces the Parse method to verify the JWT message
// using one of the keys in the given key set.
//
// The key and the JWT MUST have a proper `kid` field set.
// The key to use for signature verification is chosen by matching
// the Key ID of the JWT and the ID of the given key set.
//
// When using this option, keys MUST have a proper 'alg' field
// set. This is because we need to know the exact algorithm that
// you (the user) wants to use to verify the token. We do NOT
// trust the token's headers, because they can easily be tampered with.
//
// However, there _is_ a workaround if you do understand the risks
// of allowing a library to automatically choose a signature verification strategy,
// and you do not mind the verification process having to possibly
// attempt using multiple times before succeeding to verify. See
// `jwt.InferAlgorithmFromKey` option
//
// If you have only one key in the set, and are sure you want to
// use that key, you can use the `jwt.WithDefaultKey` option.
func WithKeySet(set jwk.Set, options ...jws.WithKeySetSuboption) ParseOption {
	options = append(append([]jws.WithKeySetSuboption(nil), jws.WithRequireKid(true)), options...)
	return &parseOption{option.New(identKeySet{}, jws.WithKeySet(set, options...))}
}

// UseDefaultKey is used in conjunction with the option WithKeySet
// to instruct the Parse method to default to the single key in a key
// set when no Key ID is included in the JWT. If the key set contains
// multiple keys then the default behavior is unchanged -- that is,
// the since we can't determine the key to use, it returns an error.
func UseDefaultKey(value bool) ParseOption {
	return &parseOption{option.New(identDefault{}, value)}
}

// WithJweHeaders is passed to "jwt.Serializer".Encrypt() method to allow
// specifying arbitrary header values to be included in the protected header
// of the JWE message
func WithJweHeaders(hdrs jwe.Headers) EncryptOption {
	return &encryptOption{option.New(identJweHeaders{}, hdrs)}
}

// WithIssuer specifies that expected issuer value. If not specified,
// the value of issuer is not verified at all.
func WithIssuer(s string) ValidateOption {
	return WithValidator(ClaimValueIs(IssuerKey, s))
}

// WithSubject specifies that expected subject value. If not specified,
// the value of subject is not verified at all.
func WithSubject(s string) ValidateOption {
	return WithValidator(ClaimValueIs(SubjectKey, s))
}

// WithJwtID specifies that expected jti value. If not specified,
// the value of jti is not verified at all.
func WithJwtID(s string) ValidateOption {
	return WithValidator(ClaimValueIs(JwtIDKey, s))
}

// WithAudience specifies that expected audience value.
// `Validate()` will return true if one of the values in the `aud` element
// matches this value.  If not specified, the value of issuer is not
// verified at all.
func WithAudience(s string) ValidateOption {
	return WithValidator(ClaimContainsString(AudienceKey, s))
}

// WithClaimValue specifies the expected value for a given claim
func WithClaimValue(name string, v interface{}) ValidateOption {
	return WithValidator(ClaimValueIs(name, v))
}

type claimPair struct {
	Name  string
	Value interface{}
}

// WithTypedClaim allows a private claim to be parsed into the object type of
// your choice. It works much like the RegisterCustomField, but the effect
// is only applicable to the jwt.Parse function call which receives this option.
//
// While this can be extremely useful, this option should be used with caution:
// There are many caveats that your entire team/user-base needs to be aware of,
// and therefore in general its use is discouraged. Only use it when you know
// what you are doing, and you document its use clearly for others.
//
// First and foremost, this is a "per-object" option. Meaning that given the same
// serialized format, it is possible to generate two objects whose internal
// representations may differ. That is, if you parse one _WITH_ the option,
// and the other _WITHOUT_, their internal representation may completely differ.
// This could potentially lead to problems.
//
// Second, specifying this option will slightly slow down the decoding process
// as it needs to consult multiple definitions sources (global and local), so
// be careful if you are decoding a large number of tokens, as the effects will stack up.
//
// Finally, this option will also NOT work unless the tokens themselves support such
// parsing mechanism. For example, while tokens obtained from `jwt.New()` and
// `openid.New()` will respect this option, if you provide your own custom
// token type, it will need to implement the TokenWithDecodeCtx interface.
func WithTypedClaim(name string, object interface{}) ParseOption {
	return &parseOption{option.New(identTypedClaim{}, claimPair{Name: name, Value: object})}
}

// WithRequiredClaim specifies that the claim identified the given name
// must exist in the token. Only the existence of the claim is checked:
// the actual value associated with that field is not checked.
func WithRequiredClaim(name string) ValidateOption {
	return WithValidator(IsRequired(name))
}

// WithMaxDelta specifies that given two claims `c1` and `c2` that represent time, the difference in
// time.Duration must be less than equal to the value specified by `d`. If `c1` or `c2` is the
// empty string, the current time (as computed by `time.Now` or the object passed via
// `WithClock()`) is used for the comparison.
//
// `c1` and `c2` are also assumed to be required, therefore not providing either claim in the
// token will result in an error.
//
// Because there is no way of reliably knowing how to parse private claims, we currently only
// support `iat`, `exp`, and `nbf` claims.
//
// If the empty string is passed to c1 or c2, then the current time (as calculated by time.Now() or
// the clock object provided via WithClock()) is used.
//
// For example, in order to specify that `exp` - `iat` should be less than 10*time.Second, you would write
//
//    jwt.Validate(token, jwt.WithMaxDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey))
//
// If AcceptableSkew of 2 second is specified, the above will return valid for any value of
// `exp` - `iat`  between 8 (10-2) and 12 (10+2).
func WithMaxDelta(dur time.Duration, c1, c2 string) ValidateOption {
	return WithValidator(MaxDeltaIs(c1, c2, dur))
}

// WithMinDelta is almost exactly the same as WithMaxDelta, but force validation to fail if
// the difference between time claims are less than dur.
//
// For example, in order to specify that `exp` - `iat` should be greater than 10*time.Second, you would write
//
//    jwt.Validate(token, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey))
//
// The validation would fail if the difference is less than 10 seconds.
//
func WithMinDelta(dur time.Duration, c1, c2 string) ValidateOption {
	return WithValidator(MinDeltaIs(c1, c2, dur))
}

type decryptParams struct {
	alg jwa.KeyAlgorithm
	key interface{}
}

type DecryptParameters interface {
	Algorithm() jwa.KeyAlgorithm
	Key() interface{}
}

func (dp *decryptParams) Algorithm() jwa.KeyAlgorithm {
	return dp.alg
}

func (dp *decryptParams) Key() interface{} {
	return dp.key
}

// WithDecrypt allows users to specify parameters for decryption using
// `jwe.Decrypt`. You must specify this if your JWT is encrypted.
//
// While `alg` accept jwa.KeyAlgorithm for convenience so you can
// directly pass the return value of `(jwk.Key).Algorithm()`, in practice
// the value must be of type jwa.SignatureAlgorithm. Otherwise the
// verification will fail
func WithDecrypt(alg jwa.KeyAlgorithm, key interface{}) ParseOption {
	return &parseOption{option.New(identDecrypt{}, &decryptParams{
		alg: alg,
		key: key,
	})}
}

// InferAlgorithmFromKey allows jwt.Parse to guess the signature algorithm
// passed to `jws.Verify()`, in case the key you provided does not have a proper `alg` header.
//
// Compared to providing explicit `alg` from the key this is slower, and in
// case our heuristics are wrong or outdated, may fail to verify the token.
// Also, automatic detection of signature verification methods are always
// more vulnerable for potential attack vectors.
//
// It is highly recommended that you fix your key to contain a proper `alg`
// header field instead of resorting to using this option, but sometimes
// it just needs to happen.
//
// Your JWT still need to have an `alg` field, and it must match one of the
// candidates that we produce for your key
func InferAlgorithmFromKey(v bool) ParseOption {
	return &parseOption{option.New(identInferAlgorithmFromKey{}, v)}
}

// WithVerifyAuto specifies that the JWS verification should be attempted
// by using the data available in the JWS message. Currently only verification
// method available is to use the keys available in the JWKS URL pointed
// in the `jku` field.
//
// The first argument should either be `nil`, or your custom jwk.SetFetcher
// object, which tells how the JWKS should be fetched. Leaving it to
// `nil` is equivalent to specifying that `jwk.Fetch` should be used.
//
// You can further pass options to customize the fetching behavior.
//
// One notable difference in the option available via the `jwt`
// package and the `jws.Verify()` or `jwk.Fetch()` functions is that
// by default all fetching is disabled unless you explicitly whitelist urls.
// Therefore, when you use this option you WILL have to specify at least
// the `jwk.WithFetchWhitelist()` suboption: as:
//
//   jwt.Parse(data, jwt.WithVerifyAuto(nil, jwk.WithFetchWhitelist(...)))
//
// See the list of available options that you can pass to `jwk.Fetch()`
// in the `jwk` package, including specifying a backoff policy by via
// `jwt.WithFetchBackoff()`
func WithVerifyAuto(f jwk.SetFetcher, options ...jwk.FetchOption) ParseOption {
	return &parseOption{option.New(identVerifyAuto{}, jws.WithVerifyAuto(f, options...))}
}
