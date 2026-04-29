package jws

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

// buildAlgHeaderJSON constructs the JSON for a protected header containing
// only the "alg" field. This is used by the precomputed header fast path.
//
// The fast path hand-builds the JSON rather than calling json.Marshal,
// so any algorithm name that would require escaping (control bytes, `"`,
// `\`, or non-ASCII) must be rejected up front. Callers that hit this
// error cannot silently fall back to the slow path because the same
// unsafe name would still appear in the emitted header.
func buildAlgHeaderJSON(alg string) ([]byte, error) {
	if !tokens.IsJSONSafeASCII(alg) {
		return nil, fmt.Errorf(`jws: algorithm name %q contains characters that would require JSON escaping`, alg)
	}
	// Construct {"alg":"<alg>"} without going through json.Marshal
	buf := make([]byte, 0, 9+len(alg))
	buf = append(buf, `{"alg":"`...)
	buf = append(buf, alg...)
	buf = append(buf, `"}`...)
	return buf, nil
}

var signatureBuilderPool = pool.New[*signatureBuilder](allocSignatureBuilder, freeSignatureBuilder)

// signatureBuilder is a transient object that is used to build
// a single JWS signature.
//
// In a multi-signature JWS message, each message is paired with
// the following:
// - a signer (the object that takes a buffer and key and generates a signature)
// - a key (the key that is used to sign the payload)
// - protected headers (the headers that are protected by the signature)
// - public headers (the headers that are not protected by the signature)
//
// This object stores all of this information in one place.
//
// This object does NOT take care of any synchronization, because it is
// meant to be used in a single-threaded context.
type signatureBuilder struct {
	alg             jwa.SignatureAlgorithm
	signer          Signer
	key             any
	protected       Headers
	public          Headers
	cachedHdrJSON   []byte // precomputed header JSON when no custom headers
	keyPrevalidated bool   // true if algorithm-key validation was done at WithKey time
}

func allocSignatureBuilder() *signatureBuilder {
	return &signatureBuilder{}
}

func freeSignatureBuilder(sb *signatureBuilder) *signatureBuilder {
	sb.alg = jwa.EmptySignatureAlgorithm()
	sb.signer = nil
	sb.key = nil
	sb.protected = nil
	sb.public = nil
	sb.cachedHdrJSON = nil
	sb.keyPrevalidated = false
	return sb
}

// buildResult holds the output of signatureBuilder.Build. In addition to
// the Signature object, it retains the raw JSON-encoded header bytes and
// the signing input buffer so callers (such as the compact serialization
// fast path) can avoid re-marshaling and re-encoding.
type buildResult struct {
	sig      Signature
	hdrbuf   []byte // raw JSON-encoded protected header
	combined []byte // signing input: base64(hdr).base64(payload)
	b64      bool   // whether payload was base64-encoded
}

func (sb *signatureBuilder) Build(sc *signContext, payload []byte) (buildResult, error) {
	var br buildResult

	// Fast path: when header JSON is precomputed (no custom headers, no kid)
	// and we're producing compact serialization, skip NewHeaders(), Set(),
	// and MarshalJSON() entirely. The JSON serialization path needs
	// br.sig.protected to be populated, so we can't use this shortcut there.
	if sb.cachedHdrJSON != nil && sc.format == fmtCompact {
		hdrbuf := sb.cachedHdrJSON
		combined := jwsbb.SignBuffer(nil, hdrbuf, payload, sc.encoder, true)

		signature, err := sb.signer.Sign(sb.key, combined)
		if err != nil {
			return br, fmt.Errorf(`failed to sign payload: %w`, err)
		}

		br.hdrbuf = hdrbuf
		br.combined = combined
		br.sig.signature = signature
		br.b64 = true
		return br, nil
	}

	// Clone caller-provided headers before mutating so that re-using the
	// same Headers instance across multiple Sign calls does not cause
	// cross-contamination of alg/kid.
	var protected Headers
	if sb.protected != nil {
		cloned, err := sb.protected.Clone()
		if err != nil {
			return br, makeSignError(prefixJwsSign, `failed to clone protected headers: %w`, err)
		}
		protected = cloned
	} else {
		protected = NewHeaders()
	}

	if err := protected.Set(AlgorithmKey, sb.alg); err != nil {
		return br, makeSignError(prefixJwsSign, `failed to set "alg" header: %w`, err)
	}

	if key, ok := sb.key.(jwk.Key); ok {
		if kid, ok := key.KeyID(); ok && kid != "" {
			// If the caller already placed a kid into the protected
			// header via WithProtectedHeaders and it disagrees with
			// the jwk.Key's kid, fail loudly. Silently preferring
			// one is a footgun in multi-kid routing setups; callers
			// who want the override should strip kid from the key or
			// omit it from the custom headers.
			if existing, ok := protected.KeyID(); ok && existing != "" && existing != kid {
				return br, makeSignError(prefixJwsSign,
					`conflicting "kid" values: jws.WithProtectedHeaders carries %q but jws.WithKey's jwk.Key carries %q — remove one`,
					existing, kid)
			}
			if err := protected.Set(KeyIDKey, kid); err != nil {
				return br, makeSignError(prefixJwsSign, `failed to set "kid" header: %w`, err)
			}
		}
	}

	// RFC 7797 §3 requires producers that set "b64":false to also list
	// "b64" in "crit". Auto-declare it in the protected header so a
	// caller who set b64=false but forgot the crit declaration does not
	// emit a non-conformant stream that strict verifiers (including
	// jws.Verify itself, since #2101) refuse. Idempotent: if "b64" is
	// already in crit, the list is unchanged. If crit is unset, it is
	// created with just "b64".
	if !getB64Value(protected) {
		crit, _ := protected.Critical()
		if !slices.Contains(crit, "b64") {
			crit = append(crit, "b64")
			if err := protected.Set(CriticalKey, crit); err != nil {
				return br, makeSignError(prefixJwsSign, `failed to set "crit" header: %w`, err)
			}
		}
	}

	// When there are no public (unprotected) headers, skip the merge
	// to avoid allocating a third Headers object just to copy into.
	hdrs := protected
	if sb.public != nil {
		var err error
		hdrs, err = mergeHeaders(sb.public, protected)
		if err != nil {
			return br, makeSignError(prefixJwsSign, `failed to merge headers: %w`, err)
		}
	}

	// raw, json format headers
	hdrbuf, err := json.Marshal(hdrs)
	if err != nil {
		return br, fmt.Errorf(`failed to marshal headers: %w`, err)
	}

	// check if we need to base64 encode the payload
	b64 := getB64Value(hdrs)
	if !b64 && !sc.detached {
		if bytes.IndexByte(payload, tokens.Period) != -1 {
			return br, fmt.Errorf(`compact serialization with b64=false requires payload to contain no "." characters per RFC 7797 §5.2; use jws.WithDetachedPayload to keep the payload out of the wire format`)
		}
	}

	combined := jwsbb.SignBuffer(nil, hdrbuf, payload, sc.encoder, b64)

	br.sig.protected = protected
	br.sig.headers = sb.public
	br.hdrbuf = hdrbuf
	br.combined = combined
	br.b64 = b64

	signature, err := sb.signer.Sign(sb.key, combined)
	if err != nil {
		return br, fmt.Errorf(`failed to sign payload: %w`, err)
	}
	br.sig.signature = signature

	return br, nil
}
