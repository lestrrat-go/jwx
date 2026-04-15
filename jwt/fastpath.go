package jwt

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

// fastPathKidSafe reports whether kid can be concatenated into a
// hand-built JSON header literal without escaping. Callers that
// receive false fall through to jws.Sign where encoding/json handles
// the escaping.
func fastPathKidSafe(kid string) bool {
	return tokens.IsJSONSafeASCII(kid)
}

// signFast reinvents the wheel a bit to avoid the overhead of
// going through the entire jws.Sign() machinery.
func signFast(t Token, alg jwa.SignatureAlgorithm, key any) ([]byte, error) {
	algstr := alg.String()
	// Unlike kid, an unsafe alg name cannot silently fall back to
	// jws.Sign: a caller that registered an algorithm with a name
	// containing JSON-special bytes is misconfigured, and slow-path
	// encoding would still produce output under that rogue alg.
	if !tokens.IsJSONSafeASCII(algstr) {
		return nil, fmt.Errorf(`jwt.signFast: algorithm name %q contains characters that would require JSON escaping`, algstr)
	}

	var kid string
	if jwkKey, ok := key.(jwk.Key); ok {
		if v, ok := jwkKey.KeyID(); ok && v != "" {
			kid = v
		}
	}

	// Setup headers
	// {"alg":"","typ":"JWT"}
	// 1234567890123456789012
	want := len(algstr) + 22
	// also, if kid != "", we need to add "kid":"$kid"
	if kid != "" {
		// "kid":""
		// 12345689
		want += len(kid) + 9
	}
	hdr := pool.ByteSlice().GetCapacity(want)
	hdr = append(hdr, '{', '"', 'a', 'l', 'g', '"', ':', '"')
	hdr = append(hdr, algstr...)
	hdr = append(hdr, '"')
	if kid != "" {
		hdr = append(hdr, ',', '"', 'k', 'i', 'd', '"', ':', '"')
		hdr = append(hdr, kid...)
		hdr = append(hdr, '"')
	}
	hdr = append(hdr, ',', '"', 't', 'y', 'p', '"', ':', '"', 'J', 'W', 'T', '"', '}')
	defer pool.ByteSlice().Put(hdr)

	// setup the buffer to sign with
	payload, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf(`jwt.signFast: failed to marshal token payload: %w`, err)
	}

	encoder := base64.DefaultEncoder()
	combined := jwsbb.SignBuffer(nil, hdr, payload, encoder, true)
	signer, err := jws.SignerFor(alg)
	if err != nil {
		return nil, fmt.Errorf(`jwt.signFast: failed to get signer for %s: %w`, alg, err)
	}

	signature, err := signer.Sign(key, combined)
	if err != nil {
		return nil, fmt.Errorf(`jwt.signFast: failed to sign payload with %s: %w`, alg, err)
	}

	// Reuse the combined buffer (base64(hdr).base64(payload)) and append .base64(sig)
	// instead of re-encoding hdr and payload from scratch via JoinCompact
	serialized := jwsbb.AppendSignature(combined, signature, encoder)
	return serialized, nil
}
