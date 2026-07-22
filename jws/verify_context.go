package jws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/lestrrat-go/option/v3"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

// verifyContext holds the state during JWS verification
type verifyContext struct {
	parseOptions       []ParseOption
	dst                *Message
	detachedPayload    []byte
	payloadReader      io.Reader
	keyProviders       []KeyProvider
	keyUsed            *any
	validateKey        bool
	critValidation     bool
	skipAlgorithmMatch bool
	criticalExtensions []string
	encoder            Base64Encoder
	//nolint:containedctx
	ctx context.Context
}

var verifyContextPool = pool.New[*verifyContext](allocVerifyContext, freeVerifyContext)

func allocVerifyContext() *verifyContext {
	return &verifyContext{
		critValidation: true,
		encoder:        base64.DefaultEncoder(),
		ctx:            context.Background(),
	}
}

func freeVerifyContext(vc *verifyContext) *verifyContext {
	vc.parseOptions = vc.parseOptions[:0]
	vc.dst = nil
	vc.detachedPayload = nil
	vc.payloadReader = nil
	vc.keyProviders = vc.keyProviders[:0]
	vc.keyUsed = nil
	vc.validateKey = false
	vc.critValidation = true
	vc.skipAlgorithmMatch = false
	vc.criticalExtensions = vc.criticalExtensions[:0]
	vc.encoder = base64.DefaultEncoder()
	vc.ctx = context.Background()
	return vc
}

func (vc *verifyContext) ProcessOptions(options []VerifyOption) error {
	var ctxOpt context.Context
	for _, opt := range options {
		switch opt.Ident() {
		case identMessage{}:
			vc.dst = option.MustGet[*Message](opt)
		case identDetachedPayload{}:
			if vc.payloadReader != nil {
				return makeVerifyError(`jws.WithDetachedPayload() and jws.WithDetachedPayloadReader() are mutually exclusive`)
			}
			vc.detachedPayload = option.MustGet[[]byte](opt)
			// RFC 7797 "b64" auto-declaration. Detached-payload
			// verification is the canonical use case for b64=false,
			// and the jws package implements b64=false handling
			// natively, so requiring callers to also pass
			// jws.WithCritExtension("b64") is busywork. We declare
			// it implicitly here so application code stays focused
			// on its own crit extensions. This does not relax any
			// other validateCritical check — the b64 header still
			// has to appear in the protected header, the crit list
			// still has to be non-empty / no duplicates / no
			// standard names, etc. Only the "is in the caller's
			// allowlist" check is short-circuited for "b64", and
			// only when WithDetachedPayload was passed.
			vc.criticalExtensions = append(vc.criticalExtensions, "b64")
		case identDetachedPayloadReader{}:
			if vc.detachedPayload != nil {
				return makeVerifyError(`jws.WithDetachedPayload() and jws.WithDetachedPayloadReader() are mutually exclusive`)
			}
			vc.payloadReader = option.MustGet[io.Reader](opt)
			// Same RFC 7797 "b64" auto-declaration as for
			// identDetachedPayload; the streaming path is the other
			// canonical use case for b64=false.
			vc.criticalExtensions = append(vc.criticalExtensions, "b64")
		case identKey{}:
			pair := option.MustGet[*withKey](opt)

			alg, ok := pair.alg.(jwa.SignatureAlgorithm)
			if !ok {
				return makeVerifyError(`expected algorithm to be of type jwa.SignatureAlgorithm but got (%[1]q, %[1]T)`, pair.alg)
			}

			if err := validateAlgorithmForKey(alg, pair.key); err != nil {
				return makeVerifyError(`%w`, err)
			}

			vc.keyProviders = append(vc.keyProviders, &staticKeyProvider{
				alg: alg,
				key: pair.key,
			})
		case identKeyProvider{}:
			vc.keyProviders = append(vc.keyProviders, option.MustGet[KeyProvider](opt))
		case identKeyUsed{}:
			vc.keyUsed = option.MustGet[*any](opt)
		case identContext{}:
			ctxOpt = option.MustGet[context.Context](opt) //nolint:fatcontext // not nesting; selecting from options
		case identValidateKey{}:
			vc.validateKey = option.MustGet[bool](opt)
		case identCritValidation{}:
			vc.critValidation = option.MustGet[bool](opt)
		case identSkipAlgorithmMatch{}:
			vc.skipAlgorithmMatch = option.MustGet[bool](opt)
		case identCritExtension{}:
			vc.criticalExtensions = append(vc.criticalExtensions, option.MustGet[[]string](opt)...)
		case identSerialization{}:
			po, ok := opt.(ParseOption)
			if !ok {
				return makeVerifyError(`invalid jws.VerifyOption: expected ParseOption`)
			}
			vc.parseOptions = append(vc.parseOptions, po)
		case identBase64Encoder{}:
			vc.encoder = option.MustGet[Base64Encoder](opt)
		default:
			return makeVerifyError(`invalid jws.VerifyOption %q passed`, `With`+strings.TrimPrefix(fmt.Sprintf(`%T`, opt.Ident()), `jws.ident`))
		}
	}
	if ctxOpt != nil {
		vc.ctx = ctxOpt
	}

	if len(vc.keyProviders) < 1 {
		return makeVerifyError(`no verifiers available. Specify an algorithm and a key using jws.WithKey() (or jws.WithKeySet(), jws.WithKeyProvider(), or jws.WithVerifyAuto())`)
	}

	// Streaming verify has a narrower option surface than the full
	// jws.Verify. The check used to fire deep inside verifyStreaming
	// after Parse; hoist it here so a malformed option combination
	// rejects before the caller's payload Reader is touched and
	// before any parse work is done.
	if vc.payloadReader != nil {
		if len(vc.keyProviders) != 1 {
			return makeVerifyError(`jws.WithDetachedPayloadReader() requires exactly one jws.WithKey(); jws.WithKeySet(), jws.WithKeyProvider() and jws.WithVerifyAuto() are not supported on the streaming path`)
		}
		if _, ok := vc.keyProviders[0].(*staticKeyProvider); !ok {
			return makeVerifyError(`jws.WithDetachedPayloadReader() requires exactly one jws.WithKey(); jws.WithKeySet(), jws.WithKeyProvider() and jws.WithVerifyAuto() are not supported on the streaming path`)
		}
	}

	return nil
}

func (vc *verifyContext) VerifyMessage(buf []byte) ([]byte, error) {
	if vc.payloadReader != nil {
		return vc.verifyStreaming(buf)
	}

	msg, err := Parse(buf, vc.parseOptions...)
	if err != nil {
		return nil, makeVerifyError(`failed to parse jws: %w`, err)
	}
	defer msg.clearRaw()

	if vc.detachedPayload != nil {
		// Reject when a "payload" member was present on the wire, even if
		// it decoded to empty bytes. A JSON JWS carrying "payload":"" is
		// an in-band JWS over an empty payload, not a detached one; only a
		// truly absent payload member (RFC 7515 Appendix F) may be
		// satisfied by a caller-supplied detached payload.
		if msg.payloadPresent {
			return nil, makeVerifyError(`can't specify detached payload for JWS with payload`)
		}

		msg.payload = vc.detachedPayload
	}

	verifyBuf := pool.ByteSlice().Get()

	// Because deferred functions bind to the current value of the variable,
	// we can't just use `defer pool.ByteSlice().Put(verifyBuf)` here.
	// Instead, we use a closure to reference the _variable_.
	// it would be better if we could call it directly, but there are
	// too many place we may return from this function
	defer func() {
		pool.ByteSlice().Put(verifyBuf)
	}()

	errs := pool.ErrorSlice().Get()
	defer func() {
		pool.ErrorSlice().Put(errs)
	}()
	for idx, sig := range msg.signatures {
		// Honor caller's deadline between signatures. Without this
		// check, a hostile JWS with many signatures keeps the loop
		// running long after the deadline; only kp.FetchKeys had
		// visibility into vc.ctx, and not every key provider observes
		// it. Cheap (~1ns) on the success path.
		if err := vc.ctx.Err(); err != nil {
			return nil, makeVerifyError(`%w`, err)
		}

		var rawHeaders []byte
		if rbp, ok := sig.protected.(interface{ rawBuffer() []byte }); ok {
			if raw := rbp.rawBuffer(); raw != nil {
				rawHeaders = raw
			}
		}

		if rawHeaders == nil {
			protected, err := json.Marshal(sig.protected)
			if err != nil {
				return nil, makeVerifyError(`failed to marshal "protected" for signature #%d: %w`, idx+1, err)
			}
			rawHeaders = protected
		}

		if vc.critValidation {
			if err := validateB64InCritIfFalse(sig.protected); err != nil {
				errs = append(errs, makeVerifyError(`signature #%d: %w`, idx+1, err))
				continue
			}
			if err := validateCritical(sig.protected, vc.criticalExtensions); err != nil {
				errs = append(errs, makeVerifyError(`signature #%d has invalid "crit" header: %w`, idx+1, err))
				continue
			}
		}

		verifyBuf = verifyBuf[:0]
		verifyBuf = jwsbb.SignBuffer(verifyBuf, rawHeaders, msg.payload, vc.encoder, msg.b64)
		var attempts int
		for i, kp := range vc.keyProviders {
			// Honor caller's deadline between key providers.
			if err := vc.ctx.Err(); err != nil {
				return nil, makeVerifyError(`%w`, err)
			}

			var sink algKeySink
			if err := kp.FetchKeys(vc.ctx, &sink, sig, msg); err != nil {
				errs = append(errs, makeVerifyError(`signature #%d: key provider %d failed: %w`, idx+1, i, err))
				continue
			}

			for _, pair := range sink.list {
				// Honor caller's deadline between (alg,key) pairs.
				// Under WithRequireKid(false) + WithInferAlgorithmFromKey(true)
				// + a large JWKS, this inner loop is the dominant
				// cost — checking ctx between attempts caps the
				// post-deadline crypto work at one operation.
				if err := vc.ctx.Err(); err != nil {
					return nil, makeVerifyError(`%w`, err)
				}

				attempts++
				alg := pair.alg
				key := pair.key

				if err := vc.tryKey(verifyBuf, alg, key, msg, sig); err != nil {
					errs = append(errs, makeVerifyError(`failed to verify signature #%d with key %T: %w`, idx+1, key, err))
					continue
				}

				return msg.payload, nil
			}
		}
		// When loose keySet options widened the candidate set above the
		// usual "kid + alg pin" of 1, name them so the operator can see
		// why a single Verify call paid N× the cost. An option-blind
		// "could not be verified with any of the keys" is the kind of
		// thing operators mis-diagnose by adding more keys instead of
		// fixing the JWS or tightening the config.
		if looseOpts := vc.namedLooseKeySetOptions(); len(looseOpts) > 0 && attempts > 1 {
			errs = append(errs, makeVerifyError(
				`signature #%d could not be verified with any of %d (alg,key) pair(s); %s widened the candidate set`,
				idx+1, attempts, strings.Join(looseOpts, " and ")))
		} else {
			errs = append(errs, makeVerifyError(`signature #%d could not be verified with any of the keys`, idx+1))
		}
	}
	return nil, makeVerifyError(`could not verify message using any of the signatures or keys: %w`, errors.Join(errs...))
}

func (vc *verifyContext) tryKey(verifyBuf []byte, alg jwa.SignatureAlgorithm, key any, msg *Message, sig *Signature) error {
	// Reject jwk.UnsupportedKey placeholders before any verifier —
	// including a custom-registered one — is selected. tryKey is the
	// single chokepoint every (alg, key) candidate funnels through, so
	// this also covers candidates from custom KeyProviders, which never
	// pass through validateAlgorithmForKey.
	if err := unsupportedKeyError(key, "signature verification"); err != nil {
		return err
	}

	// Enforce that the algorithm we are about to verify under exactly matches
	// the "alg" advertised in this signature's protected header. tryKey is the
	// single chokepoint every (alg, key) candidate funnels through, so this
	// covers all key sources (WithKey, WithKeySet, WithVerifyAuto, and
	// custom WithKeyProvider) — a provider cannot verify a message under an
	// algorithm that contradicts the message's own protected "alg". The match
	// is plain string equality: the deprecated polymorphic "EdDSA" and the
	// fully-specified "Ed25519"/"Ed448" identifiers are distinct per RFC 9864
	// and do NOT alias one another. The check fires only when the protected
	// header carries an "alg"; if "alg" is absent (for example a JSON JWS that
	// places it only in the unprotected header) we fall through unchanged.
	// VerifyCompactFast performs the equivalent cross-check on the fast path.
	// Use WithSkipAlgorithmMatch to bypass this for non-conforming producers.
	if !vc.skipAlgorithmMatch && sig.protected != nil {
		if hdrAlg, ok := sig.protected.Algorithm(); ok && hdrAlg.String() != alg.String() {
			return verifyError{verificationError{fmt.Errorf(`protected header %q %q does not match verification algorithm %q`, AlgorithmKey, hdrAlg, alg)}}
		}
	}

	if vc.validateKey {
		if err := validateKeyBeforeUse(key); err != nil {
			return fmt.Errorf(`failed to validate key before verification: %w`, err)
		}
	}

	verifier, err := VerifierFor(alg)
	if err != nil {
		return fmt.Errorf(`failed to get verifier for algorithm %q: %w`, alg, err)
	}

	if err := verifier.Verify(key, verifyBuf, sig.signature); err != nil {
		return verificationError{err}
	}

	// Verification succeeded
	if vc.keyUsed != nil {
		*vc.keyUsed = key
	}

	if vc.dst != nil {
		*(vc.dst) = *msg
	}

	return nil
}

// validateB64InCritIfFalse enforces RFC 7797 §3: producers that set
// b64=false in the protected header MUST also list "b64" in the protected
// header's "crit" array. The check runs alongside (and before)
// validateCritical so a non-conformant b64=false JWS is rejected up front
// regardless of whether the caller has supplied a crit allowlist via
// jws.WithCritExtension. Without this check, jws.Verify silently honors
// b64=false on the wire and computes its signing input differently from a
// strictly conformant verifier — exactly the cross-implementation
// disagreement RFC 7797 §6 was designed to prevent. VerifyCompactFast
// rejects any b64-bearing message outright via jws.ErrB64Present(); this
// helper is the slow-path mirror that targets only the non-conformant
// shape rather than blanket-refusing b64=false.
func validateB64InCritIfFalse(protected Headers) error {
	if getB64Value(protected) {
		return nil
	}
	if !protected.Has(CriticalKey) {
		return makeVerifyError(`protected header has "b64":false but no "crit"; RFC 7797 §3 requires producers that set "b64":false to list "b64" in "crit"`)
	}
	crit, _ := protected.Critical()
	if !slices.Contains(crit, "b64") {
		return makeVerifyError(`protected header has "b64":false but "crit" does not list "b64"; RFC 7797 §3 requires producers that set "b64":false to list "b64" in "crit"`)
	}
	return nil
}

// validateCritical checks the "crit" header per RFC 7515 Section 4.1.11.
// It enforces:
//   - the list is non-empty
//   - no entry is the empty string
//   - no entry duplicates another
//   - no entry names a standard JOSE header parameter
//   - every entry appears as a header parameter in the protected header
//   - every entry is in the caller-supplied allowedExtensions allowlist
//
// The last check is the central RFC requirement: recipients MUST reject
// any "crit" extension they do not understand, and the only way the
// library knows which extensions the caller understands is via the
// allowlist (populated from jws.WithCritExtension()).
//
// As a convenience, the RFC 7797 "b64" extension is auto-declared into
// allowedExtensions whenever the caller passes jws.WithDetachedPayload
// — see the identDetachedPayload case in ProcessOptions. The auto-
// declaration only short-circuits the allowlist check; every other
// rule above still applies to the "b64" entry.
func validateCritical(protected Headers, allowedExtensions []string) error {
	if !protected.Has(CriticalKey) {
		return nil
	}

	crit, _ := protected.Critical()
	if len(crit) == 0 {
		return makeVerifyError(`"crit" header must not be empty`)
	}

	seen := make(map[string]struct{}, len(crit))
	for _, name := range crit {
		if name == "" {
			return makeVerifyError(`"crit" header must not contain an empty extension name`)
		}
		if _, dup := seen[name]; dup {
			return makeVerifyError(`"crit" header must not contain duplicate extension %q`, name)
		}
		seen[name] = struct{}{}

		// RFC 7515 Section 4.1.11: "crit" MUST NOT include names defined
		// by the JOSE Header specification itself. The "b64" parameter
		// is RFC 7797, not RFC 7515 — listing it in "crit" is the
		// canonical use of the field per RFC 7797 §3 — so exclude it
		// from this check even though it is a typed field on stdHeaders.
		if name != B64Key && slices.Contains(stdHeaderNames, name) {
			return makeVerifyError(`"crit" header must not contain standard header parameter %q`, name)
		}

		// The extension must be present in the protected header.
		if !protected.Has(name) {
			return makeVerifyError(`"crit" header references extension %q, but it is not present in the protected header`, name)
		}

		// The recipient must have declared support for the extension.
		if !slices.Contains(allowedExtensions, name) {
			if name == B64Key {
				// b64=false is the canonical RFC 7797 case. The
				// auto-declare only fires for WithDetachedPayload /
				// WithDetachedPayloadReader; in-band b64=false still
				// requires the caller to opt in explicitly.
				return makeVerifyError(`"crit" header references extension "b64", but the recipient has not declared support for it; pass jws.WithCritExtension("b64") to accept in-band b64=false (auto-declare only fires for jws.WithDetachedPayload / jws.WithDetachedPayloadReader)`)
			}
			return makeVerifyError(`"crit" header references extension %q, but the recipient has not declared support for it (use jws.WithCritExtension(%q))`, name, name)
		}
	}

	return nil
}

// namedLooseKeySetOptions inspects the registered key providers and
// returns the human-readable names of the loose-config keySet options
// in effect for this verify call: jws.WithRequireKid(false) and/or
// jws.WithInferAlgorithmFromKey(true). These are the options whose
// presence widens the per-signature (alg,key) candidate set beyond
// the default "kid + alg pin" of one. The names are used in the final
// "could not be verified" error so an operator sees which options
// produced the fan-out without grep'ing the source.
func (vc *verifyContext) namedLooseKeySetOptions() []string {
	var requireKidFalse, inferAlgorithm bool
	for _, kp := range vc.keyProviders {
		ksp, ok := kp.(*keySetProvider)
		if !ok {
			continue
		}
		if !ksp.requireKid {
			requireKidFalse = true
		}
		if ksp.inferAlgorithm {
			inferAlgorithm = true
		}
	}
	var names []string
	if requireKidFalse {
		names = append(names, "jws.WithRequireKid(false)")
	}
	if inferAlgorithm {
		names = append(names, "jws.WithInferAlgorithmFromKey(true)")
	}
	return names
}
