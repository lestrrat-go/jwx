package jws

import (
	"fmt"
	"io"
	"strings"

	"github.com/lestrrat-go/option/v3"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

type signContext struct {
	format        int
	detached      bool
	validateKey   bool
	payload       []byte
	payloadReader io.Reader
	encoder       Base64Encoder
	none          *signatureBuilder // special signature builder
	sigbuilders   []*signatureBuilder
}

var signContextPool = pool.New[*signContext](allocSignContext, freeSignContext)

func allocSignContext() *signContext {
	return &signContext{
		format:      fmtCompact,
		sigbuilders: make([]*signatureBuilder, 0, 1),
		encoder:     base64.DefaultEncoder(),
	}
}

func freeSignContext(ctx *signContext) *signContext {
	ctx.format = fmtCompact
	for _, sb := range ctx.sigbuilders {
		signatureBuilderPool.Put(sb)
	}
	ctx.sigbuilders = ctx.sigbuilders[:0]
	ctx.detached = false
	ctx.validateKey = false
	ctx.encoder = base64.DefaultEncoder()
	ctx.none = nil
	ctx.payload = nil
	ctx.payloadReader = nil

	return ctx
}

func (sc *signContext) ProcessOptions(options []SignOption) error {
	for _, opt := range options {
		switch opt.Ident() {
		case identSerialization{}:
			sc.format = option.MustGet[int](opt)
		case identInsecureNoSignature{}:
			data := option.MustGet[*withInsecureNoSignature](opt)
			sb := signatureBuilderPool.Get()
			sb.alg = jwa.NoSignature()
			sb.protected = data.protected
			sb.signer = noneSigner{}
			sc.none = sb
			sc.sigbuilders = append(sc.sigbuilders, sb)

		case identKey{}:
			data := option.MustGet[*withKey](opt)

			alg, ok := data.alg.(jwa.SignatureAlgorithm)
			if !ok {
				return makeSignError(prefixJwsSign, `expected algorithm to be of type jwa.SignatureAlgorithm but got (%[1]q, %[1]T)`, data.alg)
			}

			// No, we don't accept "none" here.
			if alg == jwa.NoSignature() {
				return makeSignError(prefixJwsSign, `"none" (jwa.NoSignature) cannot be used with jws.WithKey`)
			}

			if !data.keyPrevalidated {
				if err := validateAlgorithmForKey(alg, data.key); err != nil {
					return makeSignError(prefixJwsSign, `%w`, err)
				}
			}

			// Surface any deferred error captured while precomputing the
			// fast-path header JSON (e.g. an algorithm name that would
			// require JSON escaping).
			if data.cachedHdrErr != nil {
				return makeSignError(prefixJwsSign, `%w`, data.cachedHdrErr)
			}

			sb := signatureBuilderPool.Get()
			sb.alg = alg
			sb.protected = data.protected
			sb.key = data.key
			sb.public = data.public
			sb.signer, _ = SignerFor(alg)
			sb.cachedHdrJSON = data.cachedHdrJSON

			sc.sigbuilders = append(sc.sigbuilders, sb)
		case identDetachedPayload{}:
			if sc.payloadReader != nil {
				return makeSignError(prefixJwsSign, `jws.WithDetachedPayload() and jws.WithDetachedPayloadReader() are mutually exclusive`)
			}
			if sc.payload != nil {
				return makeSignError(prefixJwsSign, `payload must be nil when jws.WithDetachedPayload() is specified`)
			}
			sc.payload = option.MustGet[[]byte](opt)
			sc.detached = true
		case identDetachedPayloadReader{}:
			if sc.payloadReader != nil {
				return makeSignError(prefixJwsSign, `jws.WithDetachedPayloadReader() specified more than once`)
			}
			if sc.detached {
				return makeSignError(prefixJwsSign, `jws.WithDetachedPayload() and jws.WithDetachedPayloadReader() are mutually exclusive`)
			}
			if sc.payload != nil {
				return makeSignError(prefixJwsSign, `the first argument to jws.Sign() must be nil when jws.WithDetachedPayloadReader() is used`)
			}
			sc.payloadReader = option.MustGet[io.Reader](opt)
			sc.detached = true
		case identValidateKey{}:
			sc.validateKey = option.MustGet[bool](opt)
		case identBase64Encoder{}:
			sc.encoder = option.MustGet[Base64Encoder](opt)
		default:
			return makeSignError(prefixJwsSign, `invalid jws.SignOption %q passed`, `With`+strings.TrimPrefix(fmt.Sprintf(`%T`, opt.Ident()), `jws.ident`))
		}
	}

	// Streaming sign rejects WithInsecureNoSignature up-front so the
	// caller's payload Reader is not touched. The narrower streaming
	// signer used to catch this after touching the reader.
	if sc.payloadReader != nil && sc.none != nil {
		return makeSignError(prefixJwsSign, `jws.WithInsecureNoSignature() cannot be combined with jws.WithDetachedPayloadReader(); use jws.Sign with jws.WithInsecureNoSignature() if you really need an unsecured in-memory JWS`)
	}

	return nil
}

func (sc *signContext) PopulateMessage(m *Message) error {
	m.payload = sc.payload
	m.detached = sc.detached
	m.signatures = make([]*Signature, 0, len(sc.sigbuilders))

	for i, sb := range sc.sigbuilders {
		// Create signature for each builders
		if sc.validateKey {
			if err := validateKeyBeforeUse(sb.key); err != nil {
				return fmt.Errorf(`failed to validate key for signature %d: %w`, i, err)
			}
		}

		br, err := sb.Build(sc, m.payload)
		if err != nil {
			return fmt.Errorf(`failed to build signature %d: %w`, i, err)
		}

		m.signatures = append(m.signatures, &br.sig)
	}

	return nil
}
