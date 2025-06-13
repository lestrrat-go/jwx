package jwt

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

func signFastSupportedAlgorithm(alg jwa.SignatureAlgorithm) bool {
	if signer2, err := jws.SignerFor(alg); err == nil {
		// I'm sure this check can be done once at registration time.
		// Revisit this later.
		if _, ok := signer2.(jws.RawSigner); ok {
			return true
		}
	}

	_, err := jws.NewSigner(alg)
	return err == nil
}

// signFast reinvents the wheel a bit to avoid the overhead of
// going through the entire jws.Sign() machinery.
func signFast(t Token, alg jwa.SignatureAlgorithm, key any) ([]byte, error) {
	algstr := alg.String()

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

	combined := jwsbb.SignBuffer(nil, hdr, payload, base64.DefaultEncoder(), true)

	var signature []byte
	if signer2, err := jws.SignerFor(alg); err == nil {
		// This type conversion WILL succeed, because we already checked
		//nolint:forcetypeassert
		v, err := signer2.(jws.RawSigner).SignRaw(key, combined)
		if err != nil {
			return nil, fmt.Errorf(`jwt.signFast: failed to sign payload with %s: %w`, alg, err)
		}
		signature = v
	} else {
		legacySigner, err := jws.NewSigner(alg)
		if err != nil {
			return nil, fmt.Errorf(`jwt.signFastHMAC: failed to create signer for %s: %w`, alg, err)
		}
		v, err := legacySigner.Sign(combined, key)
		if err != nil {
			return nil, fmt.Errorf(`jwt.signFast: failed to sign payload with %s: %w`, alg, err)
		}
		signature = v
	}

	serialized := jwsbb.JoinCompact(nil, hdr, payload, signature, base64.DefaultEncoder(), true)
	return serialized, nil
}
