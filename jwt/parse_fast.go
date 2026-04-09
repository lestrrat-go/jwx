package jwt

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/option/v3"
)

type fastParseCtx struct {
	alg          jwa.SignatureAlgorithm
	key          any
	validate     bool
	validateOpts []ValidateOption
	token        Token
}

// tryFastPath attempts to extract fast-path parameters from options.
// Returns true if the fast path can be used. The fastParseCtx is populated
// with the extracted values.
func tryFastPath(ctx *fastParseCtx, options []ParseOption) bool {
	ctx.validate = true // default: validation is on

	var hasKey bool
	for _, o := range options {
		if v, ok := o.(ValidateOption); ok {
			ctx.validateOpts = append(ctx.validateOpts, v)
			switch o.Ident() {
			case identContext{}:
				// ValidateOption + ParseOption, continue processing
			default:
				continue
			}
		}

		switch o.Ident() {
		case identKey{}:
			if hasKey {
				return false // multiple keys
			}
			hasKey = true

			wk := option.MustGet[*withKey](o)
			alg, ok := wk.alg.(jwa.SignatureAlgorithm)
			if !ok {
				return false // not a signature algorithm
			}
			if len(wk.options) > 0 {
				return false // has suboptions
			}
			ctx.alg = alg
			ctx.key = wk.key
		case identValidate{}:
			ctx.validate = option.MustGet[bool](o)
		case identToken{}:
			ctx.token = option.MustGet[Token](o)
		case identContext{}:
			// Already handled above as ValidateOption
		default:
			// Any other option disqualifies the fast path
			return false
		}
	}

	return hasKey
}

// parseCompactFast is the fast path for parsing JWS compact JWTs.
// It bypasses format detection, option conversion, and the nested decode loop.
func parseCompactFast(data []byte, ctx *fastParseCtx) (Token, error) {
	// Verify and extract payload via VerifyCompactFast
	// (handles SplitCompact, crit validation, sig decode, verify buffer, signature check, payload decode)
	payload, err := jws.VerifyCompactFast(ctx.key, data, ctx.alg)
	if err != nil {
		return nil, parseErrorf(`jwt.Parse`, `%w`, err)
	}

	// Build token
	token := ctx.token
	if token == nil {
		token = New()
	}

	if err := json.Unmarshal(payload, token); err != nil {
		return nil, fmt.Errorf(`failed to parse token: %w`, err)
	}

	if ctx.validate {
		if err := Validate(token, ctx.validateOpts...); err != nil {
			return nil, err
		}
	}

	return token, nil
}
