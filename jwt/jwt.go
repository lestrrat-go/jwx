//go:generate ../scripts/jwxcodegen.sh generate-jwt -objects=objects.yml
//go:generate stringer -type=TokenOption -output=token_options_gen.go

// Package jwt implements JSON Web Tokens as described in https://tools.ietf.org/html/rfc7519
package jwt

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v3"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt/internal/types"
	"github.com/lestrrat-go/option/v3"
)

var muSettings sync.Mutex
var defaultTruncation atomic.Int64
var maxParseInputSize atomic.Int64

func init() {
	maxParseInputSize.Store(10 * 1024 * 1024) // 10MB
}

// Settings controls global settings that are specific to JWTs.
func Settings(options ...GlobalOption) {
	muSettings.Lock()
	defer muSettings.Unlock()

	var flattenAudience bool
	var parsePedantic bool
	var parsePrecision = types.MaxPrecision + 1  // illegal value, so we can detect nothing was set
	var formatPrecision = types.MaxPrecision + 1 // illegal value, so we can detect nothing was set
	truncation := time.Duration(-1)
	for _, opt := range options {
		switch opt.Ident() {
		case identTruncation{}:
			truncation = option.MustGet[time.Duration](opt)
		case identFlattenAudience{}:
			flattenAudience = option.MustGet[bool](opt)
		case identNumericDateParsePedantic{}:
			parsePedantic = option.MustGet[bool](opt)
		case identNumericDateParsePrecision{}:
			v := option.MustGet[int](opt)
			// only accept this value if it's in our desired range
			if v >= 0 && v <= int(types.MaxPrecision) {
				parsePrecision = uint32(v)
			}
		case identNumericDateFormatPrecision{}:
			v := option.MustGet[int](opt)
			// only accept this value if it's in our desired range
			if v >= 0 && v <= int(types.MaxPrecision) {
				formatPrecision = uint32(v)
			}
		case identMaxParseInputSize{}:
			v := option.MustGet[int64](opt)
			if v <= 0 {
				panic("jwt.Settings: WithMaxParseInputSize must be greater than zero")
			}
			maxParseInputSize.Store(v)
		}
	}

	if parsePrecision <= types.MaxPrecision { // remember we set default to max + 1
		types.ParsePrecision.Store(parsePrecision)
	}

	if formatPrecision <= types.MaxPrecision { // remember we set default to max + 1
		types.FormatPrecision.Store(formatPrecision)
	}

	{
		var newVal uint32
		if parsePedantic {
			newVal = 1
		}
		types.Pedantic.Store(newVal)
	}

	{
		opts := TokenOptionSet(defaultOptions.Load())
		if flattenAudience {
			opts.Enable(FlattenAudience)
		} else {
			opts.Disable(FlattenAudience)
		}
		defaultOptions.Store(opts.Value())
	}

	if truncation >= 0 {
		defaultTruncation.Store(int64(truncation))
	}
}

var registry = json.NewRegistry()

// ParseString calls Parse against a string
func ParseString(s string, options ...ParseOption) (Token, error) {
	tok, err := parseBytes([]byte(s), options...)
	if err != nil {
		return nil, parseErrorf(`jwt.ParseString`, `failed to parse string: %w`, err)
	}
	return tok, nil
}

// Parse parses the JWT token payload and creates a new `jwt.Token` object.
// The token must be encoded in JWS compact format, or a raw JSON form of JWT
// without any signatures.
//
// If you need JWE support on top of JWS, you will need to rollout your
// own workaround.
//
// If the token is signed, and you want to verify the payload matches the signature,
// you must pass the jwt.WithKey(alg, key) or jwt.WithKeySet(jwk.Set) option.
// If you do not specify these parameters, no verification will be performed.
//
// During verification, if the JWS headers specify a key ID (`kid`), the
// key used for verification must match the specified ID. If you are somehow
// using a key without a `kid` (which is highly unlikely if you are working
// with a JWT from a well-know provider), you can work around this by modifying
// the `jwk.Key` and setting the `kid` header.
//
// If you also want to assert the validity of the JWT itself (i.e. expiration
// and such), use the `Validate()` function on the returned token, or pass the
// `WithValidate(true)` option. Validate options can also be passed to
// `Parse`
//
// This function takes both ParseOption and ValidateOption types:
// ParseOptions control the parsing behavior, and ValidateOptions are
// passed to `Validate()` when `jwt.WithValidate` is specified.
func Parse(s []byte, options ...ParseOption) (Token, error) {
	tok, err := parseBytes(s, options...)
	if err != nil {
		return nil, parseErrorf(`jwt.Parse`, `failed to parse token: %w`, err)
	}
	return tok, nil
}

// ParseInsecure is exactly the same as Parse(), but it disables
// signature verification and token validation.
//
// You cannot override `jwt.WithVerify()` or `jwt.WithValidate()`
// using this function. Providing these options would result in
// an error
func ParseInsecure(s []byte, options ...ParseOption) (Token, error) {
	for _, opt := range options {
		switch opt.Ident() {
		case identVerify{}, identValidate{}:
			return nil, parseErrorf(`jwt.ParseInsecure`, `jwt.WithVerify() and jwt.WithValidate() may not be specified`)
		}
	}

	options = append(options, WithVerify(false), WithValidate(false))
	tok, err := Parse(s, options...)
	if err != nil {
		return nil, parseErrorf(`jwt.ParseInsecure`, `failed to parse token: %w`, err)
	}
	return tok, nil
}

// ParseReader calls Parse against an io.Reader
func ParseReader(src io.Reader, options ...ParseOption) (Token, error) {
	maxSize := maxParseInputSize.Load()
	for _, opt := range options {
		if opt.Ident() == (identMaxParseInputSize{}) {
			maxSize = option.MustGet[int64](opt)
			if maxSize <= 0 {
				return nil, parseErrorf(`jwt.ParseReader`, `WithMaxParseInputSize must be greater than zero`)
			}
		}
	}

	data, err := io.ReadAll(io.LimitReader(src, maxSize+1))
	if err != nil {
		return nil, parseErrorf(`jwt.ParseReader`, `failed to read from token data source: %w`, err)
	}
	if int64(len(data)) > maxSize {
		return nil, parseErrorf(`jwt.ParseReader`, `input exceeded max size of %d bytes`, maxSize)
	}
	tok, err := parseBytes(data, options...)
	if err != nil {
		return nil, parseErrorf(`jwt.ParseReader`, `failed to parse token: %w`, err)
	}
	return tok, nil
}

type parseCtx struct {
	token              Token
	validateOpts       []ValidateOption
	verifyOpts         []jws.VerifyOption
	localReg           *json.Registry
	strictStringClaims *bool // per-call override; nil = use global
	pedantic           bool
	skipVerification   bool
	validate           bool
	withKeyCount       int
	withKey            *withKey // this is used to detect if we have a WithKey option
}

func parseBytes(data []byte, options ...ParseOption) (Token, error) {
	var ctx parseCtx

	// Validation is turned on by default. You need to specify
	// jwt.WithValidate(false) if you want to disable it
	ctx.validate = true

	// Verification is required (i.e., it is assumed that the incoming
	// data is in JWS format) unless the user explicitly asks for
	// it to be skipped.
	verification := true

	var verifyOpts []Option
	for _, o := range options {
		if v, ok := o.(ValidateOption); ok {
			ctx.validateOpts = append(ctx.validateOpts, v)
			// context is used for both verification and validation, so we can't just continue
			switch o.Ident() {
			case identContext{}:
			default:
				continue
			}
		}

		switch o.Ident() {
		case identKey{}:
			// it would be nice to be able to detect if ctx.verifyOpts[0]
			// is a WithKey option, but unfortunately at that point we have
			// already converted the options to a jws option, which means
			// we can no longer compare its Ident() to jwt.identKey{}.
			// So let's just count this here
			ctx.withKeyCount++
			if ctx.withKeyCount == 1 {
				ctx.withKey = option.MustGet[*withKey](o)
			}
			verifyOpts = append(verifyOpts, o)
		case identKeySet{}, identVerifyAuto{}, identKeyProvider{}, identBase64Encoder{}, identContext{}:
			verifyOpts = append(verifyOpts, o)
		case identToken{}:
			ctx.token = option.MustGet[Token](o)
		case identPedantic{}:
			ctx.pedantic = option.MustGet[bool](o)
		case identValidate{}:
			ctx.validate = option.MustGet[bool](o)
		case identVerify{}:
			verification = option.MustGet[bool](o)
		case identTypedClaim{}:
			pair := option.MustGet[claimPair](o)
			if ctx.localReg == nil {
				ctx.localReg = json.NewRegistry()
			}
			ctx.localReg.Register(pair.Name, pair.Value)
		case identStrictStringClaims{}:
			v := option.MustGet[bool](o)
			ctx.strictStringClaims = &v
		}
	}

	if !verification {
		ctx.skipVerification = true
	}

	lvo := len(verifyOpts)
	if lvo == 0 && verification {
		return nil, fmt.Errorf(`jwt.Parse: no keys for verification are provided (use jwt.WithVerify(false) to explicitly skip)`)
	}

	if lvo > 0 {
		converted, err := toVerifyOptions(verifyOpts...)
		if err != nil {
			return nil, fmt.Errorf(`jwt.Parse: failed to convert options into jws.VerifyOption: %w`, err)
		}
		ctx.verifyOpts = converted
	}

	data = bytes.TrimSpace(data)
	return parse(&ctx, data)
}

const (
	_JwsVerifyInvalid = iota
	_JwsVerifyDone
	_JwsVerifyExpectNested
	_JwsVerifySkipped
)

var _ = _JwsVerifyInvalid

func verifyJWS(ctx *parseCtx, payload []byte) ([]byte, int, error) {
	lvo := len(ctx.verifyOpts)
	if lvo == 0 {
		return nil, _JwsVerifySkipped, nil
	}

	if lvo == 1 && ctx.withKeyCount == 1 {
		wk := ctx.withKey
		alg, ok := wk.alg.(jwa.SignatureAlgorithm)
		if ok && len(wk.options) == 0 {
			verified, err := jws.VerifyCompactFast(wk.key, payload, alg)
			if err != nil {
				return nil, _JwsVerifyDone, err
			}
			return verified, _JwsVerifyDone, nil
		}
	}

	verifyOpts := append(ctx.verifyOpts, jws.WithCompact())
	verified, err := jws.Verify(payload, verifyOpts...)
	return verified, _JwsVerifyDone, err
}

// verify parameter exists to make sure that we don't accidentally skip
// over verification just because alg == ""  or key == nil or something.
func parse(ctx *parseCtx, data []byte) (Token, error) {
	payload := data
	const maxDecodeLevels = 2

	// If cty = `JWT`, we expect this to be a nested structure
	var expectNested bool

OUTER:
	for i := range maxDecodeLevels {
		switch kind := jwx.GuessFormat(payload); kind {
		case jwx.JWT:
			if ctx.pedantic {
				if expectNested {
					return nil, fmt.Errorf(`expected nested encrypted/signed payload, got raw JWT`)
				}
			}

			if i == 0 {
				// We were NOT enveloped in other formats
				if !ctx.skipVerification {
					if _, _, err := verifyJWS(ctx, payload); err != nil {
						return nil, err
					}
				}
			}

			break OUTER
		case jwx.InvalidFormat:
			return nil, UnknownPayloadTypeError()
		case jwx.UnknownFormat:
			// "Unknown" may include invalid JWTs, for example, those who lack "aud"
			// claim. We could be pedantic and reject these
			if ctx.pedantic {
				return nil, fmt.Errorf(`unknown JWT format (pedantic)`)
			}

			if i == 0 {
				// We were NOT enveloped in other formats
				if !ctx.skipVerification {
					if _, _, err := verifyJWS(ctx, payload); err != nil {
						return nil, err
					}
				}
			}
			break OUTER
		case jwx.JWS:
			// Food for thought: This is going to break if you have multiple layers of
			// JWS enveloping using different keys. It is highly unlikely use case,
			// but it might happen.

			// skipVerification should only be set to true by us. It's used
			// when we just want to parse the JWT out of a payload
			if !ctx.skipVerification {
				// nested return value means:
				// false (next envelope _may_ need to be processed)
				// true (next envelope MUST be processed)
				v, state, err := verifyJWS(ctx, payload)
				if err != nil {
					return nil, err
				}

				if state != _JwsVerifySkipped {
					payload = v

					// We only check for cty and typ if the pedantic flag is enabled
					if !ctx.pedantic {
						continue
					}

					if state == _JwsVerifyExpectNested {
						expectNested = true
						continue OUTER
					}

					// if we're not nested, we found our target. bail out of this loop
					break OUTER
				}
			}

			// No verification.
			m, err := jws.Parse(data, jws.WithCompact())
			if err != nil {
				return nil, fmt.Errorf(`invalid jws message: %w`, err)
			}
			payload = m.Payload()
		default:
			return nil, fmt.Errorf(`unsupported format (layer: #%d)`, i+1)
		}
		expectNested = false
	}

	if ctx.token == nil {
		ctx.token = New()
	}

	if ctx.localReg != nil || ctx.strictStringClaims != nil {
		dcToken, ok := ctx.token.(TokenWithDecodeCtx)
		if !ok {
			return nil, fmt.Errorf(`typed claim or strict string claims was requested, but the token (%T) does not support DecodeCtx`, ctx.token)
		}

		var strict bool
		if ctx.strictStringClaims != nil {
			strict = *ctx.strictStringClaims
		}

		dc := json.NewDecodeCtxStrictStrings(ctx.localReg, strict)
		dcToken.SetDecodeCtx(dc)
		defer func() { dcToken.SetDecodeCtx(nil) }()
	}

	if err := json.Unmarshal(payload, ctx.token); err != nil {
		return nil, fmt.Errorf(`failed to parse token: %w`, err)
	}

	if ctx.validate {
		if err := Validate(ctx.token, ctx.validateOpts...); err != nil {
			return nil, err
		}
	}
	return ctx.token, nil
}

// Sign is a convenience function to create a signed JWT token serialized in
// compact form.
//
// It accepts either a raw key (e.g. rsa.PrivateKey, ecdsa.PrivateKey, etc)
// or a jwk.Key, and the name of the algorithm that should be used to sign
// the token.
//
// For well-known algorithms with no special considerations (e.g. detached
// payloads, extra protected heders, etc), this function will automatically
// take the fast path and bypass the jws.Sign() machinery, which improves
// performance significantly.
//
// If the key is a jwk.Key and the key contains a key ID (`kid` field),
// then it is added to the protected header generated by the signature
//
// The algorithm specified in the `alg` parameter must be able to support
// the type of key you provided, otherwise an error is returned.
// For convenience `alg` is of type jwa.KeyAlgorithm so you can pass
// the return value of `(jwk.Key).Algorithm()` directly, but in practice
// it must be an instance of jwa.SignatureAlgorithm, otherwise an error
// is returned.
//
// The protected header will also automatically have the `typ` field set
// to the literal value `JWT`, unless you provide a custom value for it
// by jws.WithProtectedHeaders option, that can be passed to `jwt.WithKey“.
func Sign(t Token, options ...SignOption) ([]byte, error) {
	// fast path; can only happen if there is exactly one option
	if len(options) == 1 && (options[0].Ident() == identKey{}) {
		// The option must be a withKey option.
		wk := option.MustGet[*withKey](options[0])
		alg, ok := wk.alg.(jwa.SignatureAlgorithm)
		if !ok {
			return nil, fmt.Errorf(`jwt.Sign: invalid algorithm type %T. jwa.SignatureAlgorithm is required`, wk.alg)
		}

		// Check if option contains anything other than alg/key
		if len(wk.options) == 0 {
			// yay, we have something we can put in the FAST PATH!
			return signFast(t, alg, wk.key)
		}
		// fallthrough
	}

	var soptions []jws.SignOption
	if l := len(options); l > 0 {
		// we need to from SignOption to Option because ... reasons
		// (todo: when go1.18 prevails, use type parameters
		rawoptions := make([]Option, l)
		for i, opt := range options {
			rawoptions[i] = opt
		}

		converted, err := toSignOptions(rawoptions...)
		if err != nil {
			return nil, fmt.Errorf(`jwt.Sign: failed to convert options into jws.SignOption: %w`, err)
		}
		soptions = converted
	}
	return NewSerializer().sign(soptions...).Serialize(t)
}

// Equal compares two JWT tokens. Do not use `reflect.Equal` or the like
// to compare tokens as they will also compare extra detail such as
// sync.Mutex objects used to control concurrent access.
//
// The comparison for values is currently done using a simple equality ("=="),
// except for time.Time, which uses time.Equal after dropping the monotonic
// clock and truncating the values to 1 second accuracy.
//
// if both t1 and t2 are nil, returns true
func Equal(t1, t2 Token) bool {
	if t1 == nil && t2 == nil {
		return true
	}

	// we already checked for t1 == t2 == nil, so safe to do this
	if t1 == nil || t2 == nil {
		return false
	}

	j1, err := json.Marshal(t1)
	if err != nil {
		return false
	}

	j2, err := json.Marshal(t2)
	if err != nil {
		return false
	}

	return bytes.Equal(j1, j2)
}

func (t *stdToken) Clone() (Token, error) {
	dst := New().(*stdToken)
	dst.cloneFrom(t)
	return dst, nil
}

// CustomDecoder is a generic interface for custom field decoders.
type CustomDecoder[T any] = json.CustomDecoder[T]

// CustomDecodeFunc is a function-based implementation of CustomDecoder[T].
type CustomDecodeFunc[T any] = json.CustomDecodeFunc[T]

// RegisterCustomField registers a private claim to be decoded as type T
// using json.Unmarshal. This option has a global effect.
//
//	jwt.RegisterCustomField[time.Time](`x-birthday`)
//
// For more fine-tuned control over the decoding process,
// use RegisterCustomDecoder instead.
func RegisterCustomField[T any](name string) {
	json.RegisterTyped[T](registry, name)
}

// RegisterCustomDecoder registers a private claim with a custom decoder
// function. This option has a global effect.
//
//	jwt.RegisterCustomDecoder(`x-birthday`, jwt.CustomDecodeFunc[time.Time](func(data []byte) (time.Time, error) {
//	  var s string
//	  if err := json.Unmarshal(data, &s); err != nil {
//	    return time.Time{}, err
//	  }
//	  return time.Parse(time.RFC1123, s)
//	}))
func RegisterCustomDecoder[T any](name string, dec CustomDecodeFunc[T]) {
	json.RegisterCustomDecoder[T](registry, name, dec)
}

// UnregisterCustomField removes the registration for a custom field.
func UnregisterCustomField(name string) {
	registry.Unregister(name)
}

func getDefaultTruncation() time.Duration {
	return time.Duration(defaultTruncation.Load())
}
