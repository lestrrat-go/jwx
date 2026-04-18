//go:generate ../scripts/jwxcodegen.sh generate-jwt -objects=objects.yml
//go:generate go tool stringer -type=TokenOption -output=token_options_gen.go

package jwt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v4"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt/internal/types"
	"github.com/lestrrat-go/option/v3"
)

var muSettings sync.Mutex
var defaultTruncation atomic.Int64

// Settings controls global settings that are specific to JWTs.
func Settings(options ...GlobalOption) error {
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
		}
	}

	muSettings.Lock()
	defer muSettings.Unlock()

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

	return nil
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
// Signed input is verified by default. Pass `jwt.WithKey()`,
// `jwt.WithKeySet()`, `jwt.WithKeyProvider()`, or `jwt.WithVerifyAuto()`
// when verification is required. A bare `jwt.Parse()` call returns an error;
// to intentionally skip verification, pass `jwt.WithVerify(false)` or use
// `jwt.ParseInsecure()`.
//
// `Parse()` also accepts `ValidateOption` values. Validation runs by default
// after parsing, so `jwt.WithValidate(true)` is only needed to override a
// prior `jwt.WithValidate(false)` in the same option set. Pass
// `jwt.WithValidate(false)` if you need to defer validation and call
// `Validate()` yourself later.
//
// The default validators check only the time-based claims: `exp`
// (via `IsExpirationValid`), `nbf` (via `IsNbfValid`), and `iat`
// (via `IsIssuedAtValid`). Issuer (`iss`), audience (`aud`), subject
// (`sub`), and any other claim are NOT validated unless the caller
// explicitly requests it by passing the corresponding option, e.g.
// `jwt.WithIssuer()`, `jwt.WithAudience()`, `jwt.WithSubject()`, or a
// custom `jwt.WithValidator()`. See `jwt.Validate` for details.
//
// To produce nested JWTs, use
// `jwt.NewSerializer().Sign(...).Encrypt(...).Serialize(...)`. `Parse()` does
// not decrypt JWE envelopes; decrypt the outer JWE before calling it.
//
// During verification, if the JWS headers specify a key ID (`kid`), the
// key used for verification must match the specified ID. If you are somehow
// using a key without a `kid` (which is highly unlikely if you are working
// with a JWT from a well-known provider), you can work around this by
// modifying the `jwk.Key` and setting its `kid` field.
//
// This function takes both ParseOption and ValidateOption types:
// ParseOptions control parsing and verification behavior, and
// ValidateOptions are passed to `Validate()` when automatic validation is
// enabled.
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
// `jwt.WithVerify()` and `jwt.WithValidate()` may not be specified
// because they would conflict with the function's purpose. Likewise,
// the key-bearing options `jwt.WithKey()`, `jwt.WithKeySet()`,
// `jwt.WithKeyProvider()`, and `jwt.WithVerifyAuto()` are rejected so
// that typos like `jwt.ParseInsecure(data, jwt.WithKey(...))` cannot
// silently skip verification. Use `jwt.Parse` when a key is available.
func ParseInsecure(s []byte, options ...ParseOption) (Token, error) {
	for _, opt := range options {
		switch opt.Ident() {
		case identVerify{}, identValidate{}:
			return nil, parseErrorf(`jwt.ParseInsecure`, `jwt.WithVerify() and jwt.WithValidate() may not be specified`)
		case identKey{}, identKeySet{}, identKeyProvider{}, identVerifyAuto{}:
			return nil, parseErrorf(`jwt.ParseInsecure`, `key-bearing options (jwt.WithKey, jwt.WithKeySet, jwt.WithKeyProvider, jwt.WithVerifyAuto) may not be specified; use jwt.Parse to verify with a key`)
		}
	}

	options = append(options, WithVerify(false), WithValidate(false))
	tok, err := Parse(s, options...)
	if err != nil {
		return nil, parseErrorf(`jwt.ParseInsecure`, `failed to parse token: %w`, err)
	}
	return tok, nil
}

// ParseReader calls Parse against an io.Reader.
//
// Bounding the input size is the caller's responsibility: wrap src with
// [io.LimitReader] or [net/http.MaxBytesReader] before passing it in. See
// docs/13-input-size.md for the rationale.
func ParseReader(src io.Reader, options ...ParseOption) (Token, error) {
	data, err := io.ReadAll(src)
	if err != nil {
		return nil, parseErrorf(`jwt.ParseReader`, `failed to read from token data source: %w`, err)
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
	lenientBase64      bool // when true, skip VerifyCompactFast to use lenient base64 decoding
	withKeyCount       int
	withKey            *withKey // this is used to detect if we have a WithKey option
}

func parseBytes(data []byte, options ...ParseOption) (Token, error) {
	// Fast path: exactly one WithKey option, data looks like compact JWS.
	data = bytes.TrimSpace(data)
	var fctx fastParseCtx
	if tryFastPath(&fctx, data, options) {
		return parseCompactFast(data, &fctx)
	}

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
		case identStrictBase64Encoding{}:
			if !option.MustGet[bool](o) {
				ctx.lenientBase64 = true
			}
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

	if lvo == 1 && ctx.withKeyCount == 1 && !ctx.lenientBase64 {
		wk := ctx.withKey
		alg, ok := wk.alg.(jwa.SignatureAlgorithm)
		if ok && len(wk.options) == 0 {
			verified, err := jws.VerifyCompactFast(wk.key, payload, alg)
			if err == nil {
				return verified, _JwsVerifyDone, nil
			}
			// VerifyCompactFast refuses crit-bearing messages; on
			// that sentinel, fall through to jws.Verify below so
			// the full validateCritical rule set applies.
			if !errors.Is(err, jws.ErrCritPresent()) {
				// The fast path uses strict base64url (RFC 7515).
				// A caller whose issuer emits padded/standard
				// base64 can re-run with jwt.WithStrictBase64Encoding(false)
				// to fall back to jws.Verify's lenient decoder.
				// The error message itself doesn't point at that
				// escape hatch, so surface the hint here.
				var corrupt base64.CorruptInputError
				if errors.As(err, &corrupt) {
					return nil, _JwsVerifyDone, fmt.Errorf(
						`jwt.Parse: base64 decode failed; if the issuer emits padded/standard base64, set jwt.WithStrictBase64Encoding(false): %w`,
						err,
					)
				}
				return nil, _JwsVerifyDone, err
			}
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
			// If the key carries a kid that would require JSON escaping,
			// skip the fast path (which concatenates kid raw into the
			// protected header) and fall through to jws.Sign.
			fastSafe := true
			if jwkKey, ok := wk.key.(jwk.Key); ok {
				if v, ok := jwkKey.KeyID(); ok && !fastPathKidSafe(v) {
					fastSafe = false
				}
			}
			if fastSafe {
				// yay, we have something we can put in the FAST PATH!
				return signFast(t, alg, wk.key)
			}
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
	dst, _ := New().(*stdToken)
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
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterCustomField[T any](name string) error {
	json.RegisterTyped[T](registry, name)
	return nil
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
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterCustomDecoder[T any](name string, dec CustomDecodeFunc[T]) error {
	json.RegisterCustomDecoder[T](registry, name, dec)
	return nil
}

// UnregisterCustomField removes the registration for a custom field.
//
// The error return is reserved for future validation (for example,
// refusing to unregister a built-in field) and is always nil today.
// Callers — especially extension modules scripting Register/Unregister
// cycles from init() — should check the returned value and propagate
// on failure to stay forward-compatible, matching the convention on
// [RegisterCustomField] / [RegisterCustomDecoder].
func UnregisterCustomField(name string) error {
	registry.Unregister(name)
	return nil
}

func getDefaultTruncation() time.Duration {
	return time.Duration(defaultTruncation.Load())
}
