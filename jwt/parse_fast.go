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
	alg jwa.SignatureAlgorithm
	key any
}

// tryFastPath checks whether the fast path can be used.
// The fast path requires:
//  1. Exactly one option, which must be WithKey(SignatureAlgorithm, key) with no suboptions
//  2. The data is not JSON (first byte != '{')
//  3. The data has exactly two '.' separators (compact JWS format)
func tryFastPath(ctx *fastParseCtx, data []byte, options []ParseOption) bool {
	if len(options) != 1 || options[0].Ident() != (identKey{}) {
		return false
	}

	wk := option.MustGet[*withKey](options[0])
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
	return true
}

// parseCompactFast is the fast path for parsing JWS compact JWTs.
// It bypasses format detection, option conversion, and the nested decode loop.
// Validation is always performed (the default).
func parseCompactFast(data []byte, ctx *fastParseCtx) (Token, error) {
	payload, err := jws.VerifyCompactFast(ctx.key, data, ctx.alg)
	if err != nil {
		return nil, parseErrorf(`jwt.Parse`, `%w`, err)
	}

	token := New()
	if err := json.Unmarshal(payload, token); err != nil {
		return nil, fmt.Errorf(`failed to parse token: %w`, err)
	}

	if err := Validate(token); err != nil {
		return nil, err
	}

	return token, nil
}
