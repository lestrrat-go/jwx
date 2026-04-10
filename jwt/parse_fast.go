package jwt

import (
	"bytes"
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
