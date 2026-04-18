package jws

import (
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/option/v3"
)

type identInsecureNoSignature struct{}
type identCritExtension struct{}

// WithCritExtension declares that the caller understands and will process
// the named "crit" (Critical) header parameter extension(s) per RFC 7515
// Section 4.1.11. The option is variadic and accumulating: a single call
// may register any number of extension names, and the option may be
// passed multiple times to add more.
//
// This option takes effect when jws.WithCritValidation is enabled (the
// default in v4). With validation enabled, jws.Verify() rejects any JWS
// whose protected header lists a "crit" extension that has not been
// declared via this option, satisfying the RFC's requirement that
// recipients MUST reject any "crit" extension they do not understand.
//
// IMPORTANT: declaring an extension here is a promise to the library
// that the caller knows what the extension means and will perform any
// validation, side effect, or policy enforcement the extension requires
// AFTER jws.Verify() returns successfully. The library cannot inspect
// or enforce the semantics of an extension; it only checks that every
// "crit" entry in the message has been declared. If you register an
// extension and then forget to act on its value, you have effectively
// disabled the protection the producer was trying to obtain by listing
// the extension as critical.
//
// Concretely, the post-verify code path for a declared extension must:
//
//  1. Read the value of the named header from the verified message.
//  2. Apply whatever check or transformation the extension specifies
//     (e.g. for an "x-tenant-binding" extension, refuse to act on the
//     payload unless the binding matches the current tenant).
//  3. Treat any failure of that check as a verification failure for
//     the application's purposes, even though jws.Verify() returned
//     no error.
func WithCritExtension(names ...string) VerifyOption {
	return &verifyOption{option.New(identCritExtension{}, names)}
}

// WithJSON specifies that the result of `jws.Sign()` is serialized in
// JSON format.
//
// If you pass multiple keys to `jws.Sign()`, it will fail unless
// you also pass this option.
func WithJSON(options ...WithJSONSuboption) SignVerifyParseOption {
	var pretty bool
	for _, opt := range options {
		switch opt.Ident() {
		case identPretty{}:
			pretty = option.MustGet[bool](opt)
		}
	}

	format := fmtJSON
	if pretty {
		format = fmtJSONPretty
	}
	return &signVerifyParseOption{option.New(identSerialization{}, format)}
}

type withKey struct {
	alg             jwa.KeyAlgorithm
	key             any
	protected       Headers
	public          Headers
	cachedHdrJSON   []byte // precomputed header JSON when no custom headers and no kid
	cachedHdrErr    error  // deferred precompute error, surfaced at Sign() time
	keyPrevalidated bool   // true if algorithm-key validation was done at construction time
}

// SetProtectedDefault returns the protected headers, installing the
// supplied default when none was configured via WithProtectedHeaders.
//
// Semantics:
//   - If the caller already configured protected headers via
//     WithProtectedHeaders, those are returned unchanged; the default
//     is ignored.
//   - If none were configured and the default is non-nil, the default
//     is stored on the option and returned (making the call a side
//     effect — hence the explicit "Set" prefix).
//   - If none were configured and the default is nil, nil is returned.
//
// The method is both a getter and a conditional setter. The explicit
// name reflects the side effect so callers reviewing code do not
// mistake the call for a pure accessor.
func (w *withKey) SetProtectedDefault(v Headers) Headers {
	if w.protected == nil && v != nil {
		w.protected = v
		// Invalidate the precomputed header JSON because the caller
		// will likely modify the headers (e.g., jwt sets "typ").
		w.cachedHdrJSON = nil
		w.cachedHdrErr = nil
	}
	return w.protected
}

// WithKey is used to pass a static algorithm/key pair to either `jws.Sign()` or `jws.Verify()`.
//
// IMPORTANT: Although `alg` is typed as `jwa.KeyAlgorithm` for compatibility
// with `(jwk.Key).Algorithm()`, JWS only accepts `jwa.SignatureAlgorithm`
// values here. Passing a key-encryption algorithm such as `jwa.A128KW()` to
// `jws.WithKey()` compiles, but `jws.Sign()` / `jws.Verify()` reject it at runtime.
//
// The `alg` parameter is the identifier for the signature algorithm that should be used.
// It is of type `jwa.KeyAlgorithm` so that the value in `(jwk.Key).Algorithm()` can be
// directly passed to the option, but that is only valid when the JWK is already known to
// be intended for JWS and its `alg` value is a `jwa.SignatureAlgorithm`.
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
// # Suboptions
//
// `jws.WithKey()` accepts the following suboptions. These only take effect
// when `WithKey` is used with `jws.Sign()`; they are ignored by `jws.Verify()`:
//
//   - `jws.WithProtectedHeaders(Headers)`: JWS protected headers for this
//     signature. If the headers contain a "b64" field, the boolean value is
//     respected during serialization — `{"b64": false}` leaves the payload
//     un-base64-encoded.
//   - `jws.WithPublicHeaders(Headers)`: JWS public (unprotected) headers for
//     this signature. Only valid for JSON serialization; passing this with
//     compact serialization is an error.
//
// The suboption parameter type is `jws.WithKeySuboption`, which is a sealed
// interface distinct from `jwe.WithKeySuboption`. The Go compiler rejects any
// attempt to pass a `jwe.*` suboption to `jws.WithKey()` (and vice versa).
func WithKey(alg jwa.KeyAlgorithm, key any, options ...WithKeySuboption) SignVerifyOption {
	// Implementation note: this option is shared between Sign() and
	// Verify(). As such we don't create a KeyProvider here because
	// if used in Sign() we would be doing something else.
	var protected, public Headers
	for _, opt := range options {
		switch opt.Ident() {
		case identProtectedHeaders{}:
			protected = option.MustGet[Headers](opt)
		case identPublicHeaders{}:
			public = option.MustGet[Headers](opt)
		}
	}

	wk := &withKey{
		alg:       alg,
		key:       key,
		protected: protected,
		public:    public,
	}

	// Precompute header JSON and validate algorithm-key compatibility
	// at construction time so we can skip this work on every Sign() call.
	if salg, ok := alg.(jwa.SignatureAlgorithm); ok {
		if validateAlgorithmForKey(salg, key) == nil {
			wk.keyPrevalidated = true
		}

		// Cache header JSON when there are no custom headers and the key
		// won't inject a kid (only jwk.Key with a non-empty kid does that).
		if protected == nil && public == nil {
			needsKid := false
			if jwkKey, ok := key.(jwk.Key); ok {
				if kid, ok := jwkKey.KeyID(); ok && kid != "" {
					needsKid = true
				}
			}
			if !needsKid {
				// WithKey cannot return an error, so defer any validation
				// failure (unsafe alg characters) to Sign() time via
				// cachedHdrErr. The sign path checks this before using
				// the cached bytes.
				wk.cachedHdrJSON, wk.cachedHdrErr = buildAlgHeaderJSON(salg.String())
			}
		}
	}

	return &signVerifyOption{
		option.New(identKey{}, wk),
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
	for _, opt := range options {
		switch opt.Ident() {
		case identRequireKid{}:
			requireKid = option.MustGet[bool](opt)
		case identUseDefault{}:
			useDefault = option.MustGet[bool](opt)
		case identMultipleKeysPerKeyID{}:
			multipleKeysPerKeyID = option.MustGet[bool](opt)
		case identInferAlgorithmFromKey{}:
			inferAlgorithm = option.MustGet[bool](opt)
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

// WithVerifyAuto enables automatic verification of the signature using
// the JWKS specified in the `jku` header, via the provided jwk.Fetcher.
//
// The core jwx module is transport-agnostic: it defines the
// jwk.Fetcher interface but has no implementation. The canonical
// implementation is [github.com/jwx-go/jwkfetch]. Use it — that is
// the shape this option is designed for, and the shape the security
// guidance below is written against.
//
// # Security
//
// The `jku` header comes from the JWS you are verifying, which is
// (at the moment you are about to verify it) untrusted input. A
// hostile peer who controls the header can point the library at any
// network destination the fetcher can reach (SSRF), or hand you a
// JWKS their own server controls and have their keys accepted as
// "the issuer's keys". jwx itself does NOT prepend a default-deny
// wrapper around the fetcher — the fetcher is used as-is, and jwx
// has no way to inspect a jwk.Fetcher implementation to check
// whether it restricts URLs.
//
// **The expected pattern is to pass a jwkfetch.Client with a
// restrictive Whitelist.** jwkfetch.Client enforces the whitelist
// on the initial URL AND every redirect hop, so a hostile JWKS host
// cannot bypass the allowlist by responding with a 302 into an
// off-list URL. It is the only Fetcher implementation that jwx's
// authors test end-to-end against this option.
//
//	import "github.com/jwx-go/jwkfetch/v4"
//
//	client := jwkfetch.NewClient(
//	    jwkfetch.WithWhitelist(
//	        jwkfetch.NewMapWhitelist().Add("https://issuer.example/jwks.json"),
//	    ),
//	)
//	jws.Verify(signed, jws.WithVerifyAuto(client))
//
// If you pass a jwkfetch.Client with no WithWhitelist, it permits
// every URL — that is correct for fetching a compile-time-constant
// URL, wrong for jku verification. See jwkfetch.WithWhitelist +
// jwkfetch.NewMapWhitelist / jwkfetch.NewRegexpWhitelist for the
// common allowlist patterns.
//
// If you pass a different jwk.Fetcher implementation, YOU own the
// whitelist semantics. jwx will not and cannot check.
//
// A nil fetcher is not permitted: jku verification errors at use
// time rather than silently falling back to any default.
func WithVerifyAuto(f jwk.Fetcher) VerifyOption {
	return WithKeyProvider(jkuProvider{fetcher: f})
}

type withInsecureNoSignature struct {
	protected Headers
}

// SetProtectedDefault returns the protected headers, installing the
// supplied default when none was configured via WithProtectedHeaders.
// See (*withKey).SetProtectedDefault for the full semantics.
func (w *withInsecureNoSignature) SetProtectedDefault(v Headers) Headers {
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
	for _, opt := range options {
		switch opt.Ident() {
		case identProtectedHeaders{}:
			protected = option.MustGet[Headers](opt)
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
