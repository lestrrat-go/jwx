package jws

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"

	"github.com/lestrrat-go/dsig"
	internbase64 "github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/internal/tokens"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

// SignDetached signs a detached payload provided as an io.Reader and
// returns a JWS with an omitted payload in either compact or flattened
// JSON serialization. Unlike jws.Sign with jws.WithDetachedPayload, this
// function never materializes the payload in memory — it streams the
// payload through the hash function used by the signature algorithm.
//
// The output format is controlled by `jws.WithCompact()` or
// `jws.WithJSON()`. The default is compact. `jws.WithJSON(jws.WithPretty(true))`
// emits indented JSON. For JSON output the result is always the
// flattened form with the `"payload"` member omitted per
// RFC 7515 Appendix F; multi-signature JSON is not supported because
// the payload reader can only be consumed once.
//
// The payload must be the raw, unencoded payload — not base64url-encoded.
//
// The payload reader is consumed exactly once during signing. If
// signing fails, the reader cannot be rewound or retried.
//
// Use this function when the detached payload is too large to fit in
// memory. For payloads that fit comfortably in memory, prefer
// jws.Sign with jws.WithDetachedPayload, which supports the full
// range of algorithms and key resolution strategies.
//
// In general, rather than signing a single large payload, consider
// splitting it into smaller chunks and signing each chunk individually.
// This approach is especially important for newer digital signature
// algorithms, including Post-Quantum algorithms, which tend to require
// the entire payload to be available at signing and verification time
// and therefore do not support streaming.
//
// This function requires exactly one key via jws.WithKey(). Multiple
// keys are not supported because the payload reader can only be
// consumed once.
//
// EdDSA and custom algorithms are not supported for streaming
// signing and return an error.
func SignDetached(payload io.Reader, options ...SignOption) ([]byte, error) {
	var alg jwa.SignatureAlgorithm
	var key any
	var keyFound bool
	var validateKey bool
	var protected Headers
	var public Headers
	encoder := internbase64.DefaultEncoder()
	format := fmtCompact

	for _, option := range options {
		switch option.Ident() {
		case identKey{}:
			if keyFound {
				return nil, makeSignError(`SignDetached accepts exactly one jws.WithKey()`)
			}
			var pair *withKey
			if err := option.Value(&pair); err != nil {
				return nil, makeSignError(`invalid value for option WithKey: %w`, err)
			}
			var ok bool
			alg, ok = pair.alg.(jwa.SignatureAlgorithm)
			if !ok {
				return nil, makeSignError(`expected algorithm to be of type jwa.SignatureAlgorithm but got (%[1]q, %[1]T)`, pair.alg)
			}
			key = pair.key
			protected = pair.protected
			public = pair.public
			keyFound = true
		case identValidateKey{}:
			if err := option.Value(&validateKey); err != nil {
				return nil, makeSignError(`failed to retrieve validate-key option value: %w`, err)
			}
		case identBase64Encoder{}:
			// The header and signature segments go through this custom
			// encoder, but streamPayload uses encoding/base64 directly
			// for the b64-encoded payload path. Honoring the option on
			// two of the three segments would produce signatures that
			// only verify when the custom encoder happens to match
			// RawURLEncoding. Reject the option rather than ship a
			// silent half-use. v4 will extend Base64Encoder with a
			// streaming interface and thread it through streamPayload.
			return nil, makeSignError(`jws.WithBase64Encoder() is not supported by SignDetached; the streaming payload path uses RawURLEncoding`)
		case identSerialization{}:
			var v int
			if err := option.Value(&v); err != nil {
				return nil, makeSignError(`failed to retrieve serialization option value: %w`, err)
			}
			switch v {
			case fmtCompact, fmtJSON, fmtJSONPretty:
				format = v
			default:
				return nil, makeSignError(`invalid serialization format value %d`, v)
			}
		case identDetachedPayload{}, identKeyProvider{}, identMessage{}, identInsecureNoSignature{}:
			return nil, makeSignError(`option %T is not supported by SignDetached; use jws.WithKey() to specify a single key`, option)
		default:
			return nil, makeSignError(`invalid jws.SignOption %q passed`, `With`+strings.TrimPrefix(fmt.Sprintf(`%T`, option.Ident()), `jws.ident`))
		}
	}

	if !keyFound {
		return nil, makeSignError(`jws.WithKey() must be specified for SignDetached`)
	}

	if alg == jwa.NoSignature() {
		return nil, makeSignError(`"none" (jwa.NoSignature) cannot be used with SignDetached`)
	}

	if validateKey {
		if err := validateKeyBeforeUse(key); err != nil {
			return nil, makeSignError(`failed to validate key: %w`, err)
		}
	}

	// Resolve the dsig algorithm
	dsigAlg, ok := jwsbb.GetDsigAlgorithm(alg.String())
	if !ok {
		dsigAlg = alg.String()
	}

	dsigInfo, ok := dsig.GetAlgorithmInfo(dsigAlg)
	if !ok {
		return nil, makeSignError(`unsupported algorithm %q`, alg)
	}

	switch dsigInfo.Family {
	case dsig.EdDSAFamily:
		return nil, makeSignError(`EdDSA does not support streaming signing`)
	case dsig.Custom:
		return nil, makeSignError(`custom algorithms do not support streaming signing`)
	}

	// Convert jwk.Key to raw key for signing
	rawKey, err := convertKeyForSign(key, dsigInfo.Family)
	if err != nil {
		return nil, makeSignError(`failed to convert key: %w`, err)
	}

	// Build protected headers
	if protected == nil {
		protected = NewHeaders()
	}

	if err := protected.Set(AlgorithmKey, alg); err != nil {
		return nil, makeSignError(`failed to set "alg" header: %w`, err)
	}

	if jwkKey, ok := key.(jwk.Key); ok {
		if kid, ok := jwkKey.KeyID(); ok && kid != "" {
			if err := protected.Set(KeyIDKey, kid); err != nil {
				return nil, makeSignError(`failed to set "kid" header: %w`, err)
			}
		}
	}

	// For compact, unprotected headers have nowhere to live separately,
	// so merge them into protected before marshaling. For JSON, keep them
	// separate — protected goes into the signed input, public goes into
	// the "header" field of the output.
	var signingHeaders Headers
	if format == fmtCompact {
		signingHeaders, err = mergeHeaders(public, protected)
		if err != nil {
			return nil, makeSignError(`failed to merge headers: %w`, err)
		}
	} else {
		signingHeaders = protected
	}

	hdrbuf, err := json.Marshal(signingHeaders)
	if err != nil {
		return nil, makeSignError(`failed to marshal headers: %w`, err)
	}

	encodePayload := getB64Value(signingHeaders)

	// Create the hasher
	hasher, err := createHasher(dsigInfo, rawKey)
	if err != nil {
		return nil, makeSignError(`failed to create hasher: %w`, err)
	}

	// Build the signing prefix: base64url(header) + "."
	signingPrefix := jwsbb.SigningPrefix(nil, hdrbuf, encoder)

	if _, err := hasher.Write(signingPrefix); err != nil {
		return nil, makeSignError(`failed to write signing prefix: %w`, err)
	}

	if err := streamPayload(hasher, payload, encodePayload); err != nil {
		return nil, makeSignError(`failed to stream payload: %w`, err)
	}

	digest := hasher.Sum(nil)

	signature, err := dsig.SignDigest(rawKey, dsigAlg, digest, nil)
	if err != nil {
		return nil, makeSignError(`failed to sign digest: %w`, err)
	}

	hdrEncoded := encoder.EncodeToString(hdrbuf)
	sigEncoded := encoder.EncodeToString(signature)

	switch format {
	case fmtCompact:
		// base64url(header) + "." + "" + "." + base64url(signature)
		buf := make([]byte, 0, len(hdrEncoded)+2+len(sigEncoded))
		buf = append(buf, hdrEncoded...)
		buf = append(buf, tokens.Period, tokens.Period)
		buf = append(buf, sigEncoded...)
		return buf, nil
	case fmtJSON, fmtJSONPretty:
		return assembleDetachedJSON(public, hdrEncoded, sigEncoded, format == fmtJSONPretty)
	}
	return nil, makeSignError(`unexpected serialization format %d`, format)
}

// detachedJSONEnvelope is the flattened JSON shape produced by
// SignDetached when WithJSON() is requested. The payload member is
// intentionally absent — RFC 7515 Appendix F specifies that the JSON
// Serialization signals detached content by deleting the payload member.
// Field order matches the struct declaration order and is stable across
// encoders.
type detachedJSONEnvelope struct {
	Header    json.RawMessage `json:"header,omitempty"`
	Protected string          `json:"protected"`
	Signature string          `json:"signature"`
}

// assembleDetachedJSON builds a flattened JSON serialization with the
// payload member omitted per RFC 7515 Appendix F. Single-signature only.
func assembleDetachedJSON(public Headers, hdrEncoded, sigEncoded string, pretty bool) ([]byte, error) {
	env := detachedJSONEnvelope{
		Protected: hdrEncoded,
		Signature: sigEncoded,
	}
	if public != nil {
		hdrjs, err := json.Marshal(public)
		if err != nil {
			return nil, makeSignError(`failed to marshal unprotected header: %w`, err)
		}
		env.Header = hdrjs
	}
	if pretty {
		out, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return nil, makeSignError(`failed to marshal JSON output: %w`, err)
		}
		return out, nil
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, makeSignError(`failed to marshal JSON output: %w`, err)
	}
	return out, nil
}

// convertKeyForSign converts a jwk.Key (or raw key) to the raw key type
// expected by dsig for signing.
func convertKeyForSign(key any, family dsig.Family) (any, error) {
	if _, ok := key.(jwk.Key); !ok {
		// Already a raw key or crypto.Signer
		return key, nil
	}

	switch family {
	case dsig.HMAC:
		var rawKey []byte
		if err := keyconv.ByteSliceKey(&rawKey, key); err != nil {
			return nil, fmt.Errorf(`failed to convert HMAC key: %w`, err)
		}
		return rawKey, nil
	case dsig.RSA:
		var rawKey rsa.PrivateKey
		if err := keyconv.RSAPrivateKey(&rawKey, key); err != nil {
			return nil, fmt.Errorf(`failed to convert RSA key: %w`, err)
		}
		return &rawKey, nil
	case dsig.ECDSA:
		var rawKey ecdsa.PrivateKey
		if err := keyconv.ECDSAPrivateKey(&rawKey, key); err != nil {
			return nil, fmt.Errorf(`failed to convert ECDSA key: %w`, err)
		}
		return &rawKey, nil
	default:
		return key, nil
	}
}
