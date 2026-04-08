package jws

import (
	"context"
	"errors"
	"fmt"
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
	parseOptions    []ParseOption
	dst             *Message
	detachedPayload []byte
	keyProviders    []KeyProvider
	keyUsed         *any
	validateKey     bool
	strictCritical  bool
	encoder         Base64Encoder
	//nolint:containedctx
	ctx context.Context
}

var verifyContextPool = pool.New[*verifyContext](allocVerifyContext, freeVerifyContext)

func allocVerifyContext() *verifyContext {
	return &verifyContext{
		strictCritical: true,
		encoder:        base64.DefaultEncoder(),
		ctx:            context.Background(),
	}
}

func freeVerifyContext(vc *verifyContext) *verifyContext {
	vc.parseOptions = vc.parseOptions[:0]
	vc.dst = nil
	vc.detachedPayload = nil
	vc.keyProviders = vc.keyProviders[:0]
	vc.keyUsed = nil
	vc.validateKey = false
	vc.strictCritical = true
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
			vc.detachedPayload = option.MustGet[[]byte](opt)
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
		case identStrictCriticalHeaders{}:
			vc.strictCritical = option.MustGet[bool](opt)
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
		return makeVerifyError(`no key providers have been provided (see jws.WithKey(), jws.WithKeySet(), jws.WithVerifyAuto(), and jws.WithKeyProvider()`)
	}

	return nil
}

func (vc *verifyContext) VerifyMessage(buf []byte) ([]byte, error) {
	msg, err := Parse(buf, vc.parseOptions...)
	if err != nil {
		return nil, makeVerifyError(`failed to parse jws: %w`, err)
	}
	defer msg.clearRaw()

	if vc.detachedPayload != nil {
		if len(msg.payload) != 0 {
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

		if vc.strictCritical {
			if err := validateCritical(sig.protected); err != nil {
				errs = append(errs, makeVerifyError(`signature #%d has invalid "crit" header: %w`, idx+1, err))
				continue
			}
		}

		verifyBuf = verifyBuf[:0]
		verifyBuf = jwsbb.SignBuffer(verifyBuf, rawHeaders, msg.payload, vc.encoder, msg.b64)
		for i, kp := range vc.keyProviders {
			var sink algKeySink
			if err := kp.FetchKeys(vc.ctx, &sink, sig, msg); err != nil {
				return nil, makeVerifyError(`key provider %d failed: %w`, i, err)
			}

			for _, pair := range sink.list {
				alg := pair.alg
				key := pair.key

				if err := vc.tryKey(verifyBuf, alg, key, msg, sig); err != nil {
					errs = append(errs, makeVerifyError(`failed to verify signature #%d with key %T: %w`, idx+1, key, err))
					continue
				}

				return msg.payload, nil
			}
		}
		errs = append(errs, makeVerifyError(`signature #%d could not be verified with any of the keys`, idx+1))
	}
	return nil, makeVerifyError(`could not verify message using any of the signatures or keys: %w`, errors.Join(errs...))
}

func (vc *verifyContext) tryKey(verifyBuf []byte, alg jwa.SignatureAlgorithm, key any, msg *Message, sig *Signature) error {
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

// validateCritical checks the "crit" header per RFC 7515 Section 4.1.11.
// It verifies that all header names listed in "crit" are present in the
// protected header and are not standard JWS header parameters.
func validateCritical(protected Headers) error {
	if !protected.Has(CriticalKey) {
		return nil
	}

	crit, _ := protected.Critical()
	if len(crit) == 0 {
		return makeVerifyError(`"crit" header must not be empty`)
	}

	for _, name := range crit {
		// RFC 7515 Section 4.1.11: "crit" MUST NOT include names defined
		// by the JOSE Header specification itself.
		if slices.Contains(stdHeaderNames, name) {
			return makeVerifyError(`"crit" header must not contain standard header parameter %q`, name)
		}

		// The extension must be present in the protected header
		if !protected.Has(name) {
			return makeVerifyError(`"crit" header references extension %q, but it is not present in the protected header`, name)
		}
	}

	return nil
}

// validateCriticalFast is the fastjson-based equivalent of validateCritical,
// used by VerifyCompactFast to validate the "crit" header without full
// message parsing.
func validateCriticalFast(hdr jwsbb.Header) error {
	crit, err := jwsbb.HeaderGetStringArray(hdr, CriticalKey)
	if err != nil {
		if errors.Is(err, jwsbb.ErrHeaderNotFound()) {
			return nil
		}
		return makeVerifyError(`failed to read "crit" header: %w`, err)
	}

	if len(crit) == 0 {
		return makeVerifyError(`"crit" header must not be empty`)
	}

	for _, name := range crit {
		if slices.Contains(stdHeaderNames, name) {
			return makeVerifyError(`"crit" header must not contain standard header parameter %q`, name)
		}

		if !jwsbb.HeaderHas(hdr, name) {
			return makeVerifyError(`"crit" header references extension %q, but it is not present in the protected header`, name)
		}
	}

	return nil
}
