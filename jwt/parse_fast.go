package jwt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/option/v3"
)

type fastParseCtx struct {
	alg          jwa.SignatureAlgorithm
	key          any
	skipValidate bool
}

// tryFastPath checks whether the fast path can be used.
// The fast path requires:
//  1. One or two options: a WithKey(SignatureAlgorithm, key) with no suboptions,
//     optionally followed by WithValidate(false)
//  2. The data is not JSON (first byte != '{')
//  3. The data has exactly two '.' separators (compact JWS format)
func tryFastPath(ctx *fastParseCtx, data []byte, options []ParseOption) bool {
	if len(options) < 1 || len(options) > 2 {
		return false
	}

	// First option must be WithKey
	keyIdx := -1
	var skipValidate bool
	for i, opt := range options {
		switch opt.Ident() {
		case identKey{}:
			keyIdx = i
		case identValidate{}:
			if !option.MustGet[bool](opt) {
				skipValidate = true
			}
		default:
			return false
		}
	}

	if keyIdx < 0 {
		return false
	}

	wk := option.MustGet[*withKey](options[keyIdx])
	alg, ok := wk.alg.(jwa.SignatureAlgorithm)
	if !ok || len(wk.options) > 0 {
		return false
	}

	if len(data) == 0 || data[0] == '{' {
		return false
	}

	if bytes.Count(data, []byte{'.'}) != 2 {
		return false
	}

	ctx.alg = alg
	ctx.key = wk.key
	ctx.skipValidate = skipValidate
	return true
}

// parseCompactFast is the fast path for parsing JWS compact JWTs.
// It bypasses format detection, option conversion, and the nested decode loop.
// Validation is performed unless ctx.skipValidate is true.
func parseCompactFast(data []byte, ctx *fastParseCtx) (Token, error) {
	payload, err := jws.VerifyCompactFast(ctx.key, data, ctx.alg)
	if err != nil {
		// VerifyCompactFast refuses any header outside its minimal shape
		// (crit and b64 are specific cases of this umbrella). jwt.Parse must
		// not be laxer than jws.Verify, so fall through to the full
		// jws.Verify path: it enforces validateCritical with the
		// default-strict (empty) WithCritExtension allowlist, plus json/v2's
		// strict header decoding (e.g. duplicate-name rejection, issue
		// #2234) that the fast path's minimal-shape gate defers to it.
		if errors.Is(err, jws.ErrNonMinimalHeader()) {
			return parseCompactSlowFallback(data, ctx)
		}
		// The fast path uses strict base64url (RFC 7515). On a
		// strict-decode failure, surface a diagnosis first ("input
		// is not strict RFC 7515 base64url") and only then mention
		// the conditional remedy — the failure shape can't
		// distinguish a known-non-conforming issuer from genuinely
		// malformed / tampered input, so the caller has to make
		// that call deliberately.
		var corrupt base64.CorruptInputError
		if errors.As(err, &corrupt) {
			return nil, parseErrorf(`jwt.Parse`,
				`base64url decode failed under strict RFC 7515 rule; if the issuer is known to emit padded or standard-base64 alphabet, retry with jwt.WithStrictBase64Encoding(false), otherwise treat the input as malformed: %w`, err)
		}
		return nil, parseErrorf(`jwt.Parse`, `%w`, err)
	}

	token := New()
	if err := json.Unmarshal(payload, token); err != nil {
		return nil, fmt.Errorf(`failed to parse token: %w`, err)
	}

	if !ctx.skipValidate {
		if err := Validate(token); err != nil {
			return nil, err
		}
	}

	return token, nil
}

// parseCompactSlowFallback routes a fast-path-eligible input through
// jws.Verify so the full RFC 7515 rule set applies: the §4.1.11 "crit"
// handling, and json/v2's strict header decoding (duplicate-name rejection
// etc.) that the fast path's minimal-shape gate defers here. Reached only
// when the protected header actually contains "crit", is non-minimal, or
// fails to split, so the extra cost is limited to adversarial / unusual
// inputs.
func parseCompactSlowFallback(data []byte, ctx *fastParseCtx) (Token, error) {
	payload, err := jws.Verify(data, jws.WithCompact(), jws.WithKey(ctx.alg, ctx.key))
	if err != nil {
		return nil, parseErrorf(`jwt.Parse`, `%w`, err)
	}

	token := New()
	if err := json.Unmarshal(payload, token); err != nil {
		return nil, fmt.Errorf(`failed to parse token: %w`, err)
	}

	if !ctx.skipValidate {
		if err := Validate(token); err != nil {
			return nil, err
		}
	}

	return token, nil
}
