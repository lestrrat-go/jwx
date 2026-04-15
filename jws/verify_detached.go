package jws

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/dsig"
	internbase64 "github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/internal/tokens"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

// VerifyDetached verifies a JWS against a detached payload provided as
// an io.Reader. The input may be a compact serialization with an empty
// payload segment, or a flattened JSON serialization with the "payload"
// member omitted or empty. Unlike jws.Verify with jws.WithDetachedPayload,
// this function never materializes the payload in memory — it streams
// the payload through the hash function used by the signature algorithm.
//
// The input format is auto-detected by the first non-whitespace byte
// (`{` → JSON, otherwise compact). Passing jws.WithCompact() or
// jws.WithJSON() overrides auto-detection.
//
// The payload must be the raw, unencoded payload — not base64url-encoded.
//
// The payload reader is consumed exactly once during verification. If
// verification fails, the reader cannot be rewound or retried.
//
// Use this function when the detached payload is too large to fit in
// memory. For payloads that fit comfortably in memory, prefer
// jws.Verify with jws.WithDetachedPayload, which supports the full
// range of algorithms and key resolution strategies.
//
// In general, rather than signing a single large payload, consider
// splitting it into smaller chunks and signing each chunk individually.
// This approach is especially important for newer digital signature
// algorithms, including Post-Quantum algorithms, which tend to require
// the entire payload to be available at signing and verification time
// and therefore do not support streaming.
//
// For JSON input, only flattened or single-entry general serialization
// is supported; multi-signature JSON is rejected because the payload
// reader can only be consumed once. Unprotected ("header") fields are
// not surfaced to the caller.
//
// This function requires exactly one key via jws.WithKey(). Key sets
// and key providers are not supported because the payload reader can
// only be consumed once.
//
// EdDSA and custom algorithms are not supported for streaming
// verification and return an error.
func VerifyDetached(compact []byte, payload io.Reader, options ...VerifyOption) error {
	// Extract the single key from options. We do not use verifyContext
	// because VerifyDetached is a single-key operation — key sets and
	// key providers are not supported.
	var alg jwa.SignatureAlgorithm
	var key any
	var keyFound bool
	var validateKey bool
	var critValidation bool
	// VerifyDetached is always detached, so "b64" is pre-declared
	// in the allowlist — matches the auto-declaration that
	// verifyContext does for jws.Verify + WithDetachedPayload.
	criticalExtensions := []string{"b64"}
	var keyUsed any
	format := 0

	for _, option := range options {
		switch option.Ident() {
		case identKey{}:
			if keyFound {
				return makeVerifyError(`VerifyDetached accepts exactly one jws.WithKey()`)
			}
			var pair *withKey
			if err := option.Value(&pair); err != nil {
				return makeVerifyError(`invalid value for option WithKey: %w`, err)
			}
			var ok bool
			alg, ok = pair.alg.(jwa.SignatureAlgorithm)
			if !ok {
				return makeVerifyError(`expected algorithm to be of type jwa.SignatureAlgorithm but got (%[1]q, %[1]T)`, pair.alg)
			}
			key = pair.key
			keyFound = true
		case identValidateKey{}:
			if err := option.Value(&validateKey); err != nil {
				return makeVerifyError(`failed to retrieve validate-key option value: %w`, err)
			}
		case identCritValidation{}:
			if err := option.Value(&critValidation); err != nil {
				return makeVerifyError(`failed to retrieve crit-validation option value: %w`, err)
			}
		case identCritExtension{}:
			var names []string
			if err := option.Value(&names); err != nil {
				return makeVerifyError(`failed to retrieve crit-extension option value: %w`, err)
			}
			criticalExtensions = append(criticalExtensions, names...)
		case identKeyUsed{}:
			if err := option.Value(&keyUsed); err != nil {
				return makeVerifyError(`failed to retrieve key-used option value: %w`, err)
			}
		case identBase64Encoder{}:
			// streamPayload uses encoding/base64 directly for the
			// b64-encoded payload path, so honoring a custom encoder
			// would silently apply to the protected-header decode but
			// not the payload. Reject symmetrically with SignDetached
			// rather than ship a half-use. v4 will extend
			// Base64Encoder with a streaming interface and thread it
			// through streamPayload.
			return makeVerifyError(`jws.WithBase64Encoder() is not supported by VerifyDetached; the streaming payload path uses RawURLEncoding`)
		case identSerialization{}:
			var v int
			if err := option.Value(&v); err != nil {
				return makeVerifyError(`failed to retrieve serialization option value: %w`, err)
			}
			switch v {
			case fmtCompact:
				format = fmtCompact
			case fmtJSON, fmtJSONPretty:
				format = fmtJSON
			default:
				return makeVerifyError(`invalid serialization format value %d`, v)
			}
		case identKeyProvider{}, identDetachedPayload{}, identMessage{}:
			return makeVerifyError(`option %T is not supported by VerifyDetached; use jws.WithKey() to specify a single key`, option)
		default:
			return makeVerifyError(`invalid jws.VerifyOption %q passed`, `With`+strings.TrimPrefix(fmt.Sprintf(`%T`, option.Ident()), `jws.ident`))
		}
	}

	if !keyFound {
		return makeVerifyError(`jws.WithKey() must be specified for VerifyDetached`)
	}

	detected := detectDetachedFormat(compact)
	if detected == 0 {
		return makeVerifyError(`input is empty or whitespace-only`)
	}
	if format == 0 {
		format = detected
	} else if format != detected {
		return makeVerifyError(`input format mismatch: %s specified but input appears to be %s`, detachedFormatName(format), detachedFormatName(detected))
	}

	if validateKey {
		if err := validateKeyBeforeUse(key); err != nil {
			return makeVerifyError(`failed to validate key: %w`, err)
		}
	}

	// Resolve the dsig algorithm
	dsigAlg, ok := jwsbb.GetDsigAlgorithm(alg.String())
	if !ok {
		dsigAlg = alg.String()
	}

	dsigInfo, ok := dsig.GetAlgorithmInfo(dsigAlg)
	if !ok {
		return makeVerifyError(`unsupported algorithm %q`, alg)
	}

	switch dsigInfo.Family {
	case dsig.EdDSAFamily:
		return makeVerifyError(`EdDSA does not support streaming verification`)
	case dsig.Custom:
		return makeVerifyError(`custom algorithms do not support streaming verification`)
	}

	// Convert jwk.Key to raw key for dsig
	rawKey, err := convertKeyForVerify(key, dsigInfo.Family)
	if err != nil {
		return makeVerifyError(`failed to convert key: %w`, err)
	}

	protectedB64, decodedSig, err := extractDetachedParts(compact, format)
	if err != nil {
		return makeVerifyError(`failed to extract detached parts: %w`, err)
	}

	rawHeaders, err := internbase64.Decode(protectedB64)
	if err != nil {
		return makeVerifyError(`failed to decode protected header: %w`, err)
	}

	// Parse the header to get b64
	hdr := NewHeaders()
	if err := json.Unmarshal(rawHeaders, hdr); err != nil {
		return makeVerifyError(`failed to parse protected header: %w`, err)
	}

	encodePayload := getB64Value(hdr)

	if critValidation {
		if err := validateCritical(hdr, criticalExtensions); err != nil {
			return makeVerifyError(`invalid "crit" header: %w`, err)
		}
	}

	// Create the hasher
	hasher, err := createHasher(dsigInfo, rawKey)
	if err != nil {
		return makeVerifyError(`failed to create hasher: %w`, err)
	}

	// Write the signing prefix: base64url(header) + "." — use the
	// original protected bytes verbatim so the recomputed signing input
	// matches what was signed (re-encoding parsed headers is not
	// guaranteed to produce identical bytes).
	if _, err := hasher.Write(protectedB64); err != nil {
		return makeVerifyError(`failed to write signing prefix: %w`, err)
	}
	if _, err := hasher.Write([]byte{tokens.Period}); err != nil {
		return makeVerifyError(`failed to write signing prefix: %w`, err)
	}

	if err := streamPayload(hasher, payload, encodePayload); err != nil {
		return makeVerifyError(`failed to stream payload: %w`, err)
	}

	digest := hasher.Sum(nil)

	if err := dsig.VerifyDigest(rawKey, dsigAlg, digest, decodedSig); err != nil {
		return makeVerifyError(`failed to verify signature: %w`, verificationError{err})
	}

	if keyUsed != nil {
		if err := blackmagic.AssignIfCompatible(keyUsed, key); err != nil {
			return makeVerifyError(`failed to assign used key (%T) to %T: %w`, key, keyUsed, err)
		}
	}

	return nil
}

// detachedFormatName returns a human-readable name for the internal
// format constant, used to produce clear mismatch errors when the
// caller-asserted format disagrees with auto-detection.
func detachedFormatName(f int) string {
	switch f {
	case fmtCompact:
		return `jws.WithCompact()`
	case fmtJSON, fmtJSONPretty:
		return `jws.WithJSON()`
	default:
		return fmt.Sprintf(`unknown(%d)`, f)
	}
}

// detectDetachedFormat inspects the first non-whitespace byte to decide
// whether the input is a compact or JSON JWS. Returns 0 if the input is
// empty or whitespace-only. Mirrors jws.Parse auto-detection.
func detectDetachedFormat(src []byte) int {
	for _, b := range src {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if b == tokens.OpenCurlyBracket {
			return fmtJSON
		}
		return fmtCompact
	}
	return 0
}

// extractDetachedParts routes to the compact or JSON parser and returns
// the raw base64url-encoded protected header and the decoded signature
// bytes. The protected header is returned as-is (not decoded) so the
// signing input can be reconstructed byte-for-byte.
func extractDetachedParts(src []byte, format int) ([]byte, []byte, error) {
	switch format {
	case fmtCompact:
		protectedB64, payloadSegment, signatureSegment, err := jwsbb.SplitCompact(src)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to split compact: %w`, err)
		}
		if len(payloadSegment) != 0 {
			return nil, nil, fmt.Errorf(`compact token must have an empty payload segment for VerifyDetached`)
		}
		decodedSig, err := internbase64.Decode(signatureSegment)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to decode signature: %w`, err)
		}
		return protectedB64, decodedSig, nil
	case fmtJSON, fmtJSONPretty:
		protectedB64, signatureB64, err := parseDetachedJSON(src)
		if err != nil {
			return nil, nil, err
		}
		decodedSig, err := internbase64.Decode(signatureB64)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to decode signature: %w`, err)
		}
		return protectedB64, decodedSig, nil
	}
	return nil, nil, fmt.Errorf(`unexpected serialization format %d`, format)
}

// detachedJSONProbe is a probe struct used to parse a flattened or
// single-signature general JSON-serialized JWS for VerifyDetached.
// Fields are pointers so we can distinguish "absent" from "empty".
type detachedJSONProbe struct {
	Payload    *string           `json:"payload,omitempty"`
	Protected  *string           `json:"protected,omitempty"`
	Header     json.RawMessage   `json:"header,omitempty"`
	Signature  *string           `json:"signature,omitempty"`
	Signatures []json.RawMessage `json:"signatures,omitempty"`
}

// detachedJSONSignatureProbe is used to parse an entry in the
// "signatures" array of a general-form JWS.
type detachedJSONSignatureProbe struct {
	Protected *string         `json:"protected,omitempty"`
	Header    json.RawMessage `json:"header,omitempty"`
	Signature *string         `json:"signature,omitempty"`
}

// parseDetachedJSON extracts the base64url-encoded protected header and
// signature from a JSON-serialized JWS with an omitted or empty payload.
// Accepts the flattened form and the general form with exactly one
// signature entry. Rejects multi-signature JSON.
func parseDetachedJSON(src []byte) ([]byte, []byte, error) {
	var probe detachedJSONProbe
	if err := json.Unmarshal(src, &probe); err != nil {
		return nil, nil, fmt.Errorf(`failed to parse JSON serialization: %w`, err)
	}

	if probe.Payload != nil && *probe.Payload != "" {
		return nil, nil, fmt.Errorf(`JSON input must have an omitted or empty "payload" member for VerifyDetached`)
	}

	var protectedB64, signatureB64 *string
	switch {
	case probe.Signature != nil:
		if len(probe.Signatures) > 0 {
			return nil, nil, fmt.Errorf(`JSON input has both "signature" and "signatures"`)
		}
		protectedB64 = probe.Protected
		signatureB64 = probe.Signature
	case len(probe.Signatures) == 1:
		var sig detachedJSONSignatureProbe
		if err := json.Unmarshal(probe.Signatures[0], &sig); err != nil {
			return nil, nil, fmt.Errorf(`failed to parse signatures[0]: %w`, err)
		}
		protectedB64 = sig.Protected
		signatureB64 = sig.Signature
	case len(probe.Signatures) > 1:
		return nil, nil, fmt.Errorf(`VerifyDetached supports only single-signature JSON input, got %d`, len(probe.Signatures))
	default:
		return nil, nil, fmt.Errorf(`JSON input has no signature`)
	}

	if protectedB64 == nil {
		return nil, nil, fmt.Errorf(`JSON input is missing "protected" member`)
	}
	if signatureB64 == nil {
		return nil, nil, fmt.Errorf(`JSON input is missing "signature" member`)
	}
	return []byte(*protectedB64), []byte(*signatureB64), nil
}

// createHasher returns the appropriate hash.Hash for the given algorithm info and key.
// For HMAC: returns hmac.New(hashFunc, key).
// For RSA/ECDSA: returns hashFunc.New() (key is ignored).
func createHasher(info dsig.AlgorithmInfo, key any) (hash.Hash, error) {
	switch info.Family {
	case dsig.HMAC:
		meta, ok := info.Meta.(dsig.HMACFamilyMeta)
		if !ok {
			return nil, fmt.Errorf(`invalid HMAC metadata`)
		}
		keyBytes, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf(`HMAC key must be []byte, got %T`, key)
		}
		return hmac.New(meta.HashFunc, keyBytes), nil
	case dsig.RSA:
		meta, ok := info.Meta.(dsig.RSAFamilyMeta)
		if !ok {
			return nil, fmt.Errorf(`invalid RSA metadata`)
		}
		return meta.Hash.New(), nil
	case dsig.ECDSA:
		meta, ok := info.Meta.(dsig.ECDSAFamilyMeta)
		if !ok {
			return nil, fmt.Errorf(`invalid ECDSA metadata`)
		}
		return meta.Hash.New(), nil
	default:
		return nil, fmt.Errorf(`unsupported algorithm family %q for streaming`, info.Family)
	}
}

// convertKeyForVerify converts a jwk.Key (or raw key) to the raw key type
// expected by dsig for verification.
func convertKeyForVerify(key any, family dsig.Family) (any, error) {
	if _, ok := key.(jwk.Key); !ok {
		// Already a raw key
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
		var rawKey rsa.PublicKey
		if err := keyconv.RSAPublicKey(&rawKey, key); err != nil {
			return nil, fmt.Errorf(`failed to convert RSA key: %w`, err)
		}
		return &rawKey, nil
	case dsig.ECDSA:
		var rawKey ecdsa.PublicKey
		if err := keyconv.ECDSAPublicKey(&rawKey, key); err != nil {
			return nil, fmt.Errorf(`failed to convert ECDSA key: %w`, err)
		}
		return &rawKey, nil
	default:
		return key, nil
	}
}

// streamPayload streams the payload through the hasher.
// If encodePayload is true, the payload is base64url-encoded before being written to the hasher.
func streamPayload(hasher hash.Hash, payload io.Reader, encodePayload bool) error {
	if encodePayload {
		encoder := base64.NewEncoder(base64.RawURLEncoding, hasher)
		if _, err := io.Copy(encoder, payload); err != nil {
			return fmt.Errorf(`failed to stream payload through base64 encoder: %w`, err)
		}
		if err := encoder.Close(); err != nil {
			return fmt.Errorf(`failed to close base64 encoder: %w`, err)
		}
		return nil
	}

	if _, err := io.Copy(hasher, payload); err != nil {
		return fmt.Errorf(`failed to stream payload: %w`, err)
	}
	return nil
}
