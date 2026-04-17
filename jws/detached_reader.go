package jws

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	stdbase64 "encoding/base64"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/lestrrat-go/dsig"
	"github.com/lestrrat-go/option/v3"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/keyconv"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

const (
	prefixJwsSignDetachedReader = `jws.SignDetachedReader`
)

// SignDetachedReader signs a detached payload provided as an io.Reader and
// returns a JWS with the payload omitted from either compact or flattened JSON
// serialization.
//
// This is a specialist API for one-pass detached payloads that should not be
// materialized in memory. If the detached payload already fits comfortably in
// memory, prefer jws.Sign with jws.WithDetachedPayload(), which supports the
// full option and algorithm surface.
//
// The output format is controlled by jws.WithCompact() or jws.WithJSON().
// Compact is the default. JSON output is always the flattened single-signature
// form with the "payload" member omitted per RFC 7515 Appendix F.
//
// This function requires exactly one jws.WithKey() option. It rejects key
// sets, key providers, and algorithms that require the full payload at
// sign-time such as EdDSA and dsig custom-family algorithms.
//
// The payload reader is consumed exactly once. On signing failure the reader
// cannot be rewound or retried; callers that need retry semantics must either
// buffer the payload themselves or use jws.Sign with jws.WithDetachedPayload().
func SignDetachedReader(payload io.Reader, options ...SignOption) ([]byte, error) {
	var alg jwa.SignatureAlgorithm
	var key any
	var keyFound bool
	var validateKey bool
	var protected Headers
	var public Headers
	var encoder Base64Encoder = base64.DefaultEncoder()
	format := fmtCompact

	for _, opt := range options {
		switch opt.Ident() {
		case identKey{}:
			if keyFound {
				return nil, makeSignError(prefixJwsSignDetachedReader, `SignDetachedReader accepts exactly one jws.WithKey(); use jws.Sign with jws.WithDetachedPayload() for the general detached path`)
			}

			pair := option.MustGet[*withKey](opt)
			var ok bool
			alg, ok = pair.alg.(jwa.SignatureAlgorithm)
			if !ok {
				return nil, makeSignError(prefixJwsSignDetachedReader, `expected algorithm to be of type jwa.SignatureAlgorithm but got (%[1]q, %[1]T)`, pair.alg)
			}
			if alg != jwa.NoSignature() && !pair.keyPrevalidated {
				if err := validateAlgorithmForKey(alg, pair.key); err != nil {
					return nil, makeSignError(prefixJwsSignDetachedReader, `%w`, err)
				}
			}
			if pair.cachedHdrErr != nil {
				return nil, makeSignError(prefixJwsSignDetachedReader, `%w`, pair.cachedHdrErr)
			}

			key = pair.key
			protected = pair.protected
			public = pair.public
			keyFound = true
		case identValidateKey{}:
			validateKey = option.MustGet[bool](opt)
		case identBase64Encoder{}:
			return nil, makeSignError(prefixJwsSignDetachedReader, `jws.WithBase64Encoder() is not supported by SignDetachedReader; the streaming payload path uses RawURLEncoding`)
		case identSerialization{}:
			v := option.MustGet[int](opt)
			switch v {
			case fmtCompact, fmtJSON, fmtJSONPretty:
				format = v
			default:
				return nil, makeSignError(prefixJwsSignDetachedReader, `invalid serialization format value %d`, v)
			}
		case identDetachedPayload{}, identKeyProvider{}, identMessage{}, identInsecureNoSignature{}:
			return nil, makeSignError(prefixJwsSignDetachedReader, `option %T is not supported by SignDetachedReader; use jws.Sign with jws.WithDetachedPayload() for the general detached path`, opt)
		default:
			return nil, makeSignError(prefixJwsSignDetachedReader, `invalid jws.SignOption %q passed`, `With`+strings.TrimPrefix(fmt.Sprintf(`%T`, opt.Ident()), `jws.ident`))
		}
	}

	if !keyFound {
		return nil, makeSignError(prefixJwsSignDetachedReader, `jws.WithKey() must be specified for SignDetachedReader`)
	}
	if alg == jwa.NoSignature() {
		return nil, makeSignError(prefixJwsSignDetachedReader, `"none" (jwa.NoSignature) cannot be used with SignDetachedReader; use jws.Sign with jws.WithInsecureNoSignature() if you really need an unsecured in-memory JWS`)
	}

	if validateKey {
		if err := validateKeyBeforeUse(key); err != nil {
			return nil, makeSignError(prefixJwsSignDetachedReader, `failed to validate key: %w`, err)
		}
	}

	dsigAlg := resolveDetachedDsigAlgorithm(alg.String())
	dsigInfo, ok := dsig.GetAlgorithmInfo(dsigAlg)
	if !ok {
		return nil, makeSignError(prefixJwsSignDetachedReader, `unsupported algorithm %q; use jws.Sign with jws.WithDetachedPayload() if you need the general detached path`, alg)
	}
	switch dsigInfo.Family {
	case dsig.EdDSAFamily:
		return nil, makeSignError(prefixJwsSignDetachedReader, `algorithm %q does not support SignDetachedReader because it requires the full payload; use jws.Sign with jws.WithDetachedPayload() if the payload fits in memory`, alg)
	case dsig.Custom:
		return nil, makeSignError(prefixJwsSignDetachedReader, `custom algorithms do not support SignDetachedReader; use jws.Sign with jws.WithDetachedPayload() if the payload fits in memory`)
	}

	rawKey, err := convertKeyForDetachedSign(key, dsigInfo.Family)
	if err != nil {
		return nil, makeSignError(prefixJwsSignDetachedReader, `failed to convert key: %w`, err)
	}

	protected, err = cloneOrNewHeaders(protected)
	if err != nil {
		return nil, makeSignError(prefixJwsSignDetachedReader, `failed to clone protected headers: %w`, err)
	}
	if err := protected.Set(AlgorithmKey, alg); err != nil {
		return nil, makeSignError(prefixJwsSignDetachedReader, `failed to set "alg" header: %w`, err)
	}
	if jwkKey, ok := key.(jwk.Key); ok {
		if kid, ok := jwkKey.KeyID(); ok && kid != "" {
			if err := protected.Set(KeyIDKey, kid); err != nil {
				return nil, makeSignError(prefixJwsSignDetachedReader, `failed to set "kid" header: %w`, err)
			}
		}
	}

	signingHeaders := protected
	if format == fmtCompact {
		signingHeaders, err = mergeHeaders(public, protected)
		if err != nil {
			return nil, makeSignError(prefixJwsSignDetachedReader, `failed to merge headers: %w`, err)
		}
	}

	hdrbuf, err := json.Marshal(signingHeaders)
	if err != nil {
		return nil, makeSignError(prefixJwsSignDetachedReader, `failed to marshal headers: %w`, err)
	}

	hasher, err := createDetachedHasher(dsigInfo, rawKey)
	if err != nil {
		return nil, makeSignError(prefixJwsSignDetachedReader, `failed to create hasher: %w`, err)
	}
	if err := writeDetachedPrefix(hasher, hdrbuf, encoder); err != nil {
		return nil, makeSignError(prefixJwsSignDetachedReader, `failed to write signing prefix: %w`, err)
	}
	if err := streamDetachedPayload(hasher, payload, getB64Value(signingHeaders)); err != nil {
		return nil, makeSignError(prefixJwsSignDetachedReader, `failed to stream payload: %w`, err)
	}

	signature, err := dsig.SignDigest(rawKey, dsigAlg, hasher.Sum(nil), nil)
	if err != nil {
		return nil, makeSignError(prefixJwsSignDetachedReader, `failed to sign digest: %w`, err)
	}

	hdrEncoded := encoder.EncodeToString(hdrbuf)
	sigEncoded := encoder.EncodeToString(signature)

	switch format {
	case fmtCompact:
		buf := make([]byte, 0, len(hdrEncoded)+2+len(sigEncoded))
		buf = append(buf, hdrEncoded...)
		buf = append(buf, tokens.Period, tokens.Period)
		buf = append(buf, sigEncoded...)
		return buf, nil
	case fmtJSON, fmtJSONPretty:
		return assembleDetachedJSON(public, hdrEncoded, sigEncoded, format == fmtJSONPretty)
	default:
		return nil, makeSignError(prefixJwsSignDetachedReader, `unexpected serialization format %d`, format)
	}
}

// VerifyDetachedReader verifies a JWS against a detached payload provided as
// an io.Reader. The JWS input may be compact or single-signature JSON.
//
// This is a specialist API for one-pass detached payloads that should not be
// materialized in memory. If the detached payload already fits comfortably in
// memory, prefer jws.Verify with jws.WithDetachedPayload(), which supports the
// full option and algorithm surface.
//
// The input format is auto-detected unless the caller explicitly passes
// jws.WithCompact() or jws.WithJSON(). A mismatch between the asserted format
// and the detected input format is rejected with a clear error.
//
// This function requires exactly one jws.WithKey() option. It rejects key
// sets, key providers, and algorithms that require the full payload at
// verify-time such as EdDSA and dsig custom-family algorithms.
//
// The payload reader is consumed exactly once. On verification failure the
// reader cannot be rewound or retried; callers that need retry semantics
// must either buffer the payload themselves or use jws.Verify with
// jws.WithDetachedPayload().
func VerifyDetachedReader(src []byte, payload io.Reader, options ...VerifyOption) error {
	var alg jwa.SignatureAlgorithm
	var key any
	var keyFound bool
	var validateKey bool
	var keyUsed *any
	critValidation := true
	criticalExtensions := []string{"b64"}
	format := 0

	for _, opt := range options {
		switch opt.Ident() {
		case identKey{}:
			if keyFound {
				return makeVerifyError(`VerifyDetachedReader accepts exactly one jws.WithKey(); use jws.Verify with jws.WithDetachedPayload() for the general detached path`)
			}

			pair := option.MustGet[*withKey](opt)
			var ok bool
			alg, ok = pair.alg.(jwa.SignatureAlgorithm)
			if !ok {
				return makeVerifyError(`expected algorithm to be of type jwa.SignatureAlgorithm but got (%[1]q, %[1]T)`, pair.alg)
			}
			if alg != jwa.NoSignature() {
				if err := validateAlgorithmForKey(alg, pair.key); err != nil {
					return makeVerifyError(`%w`, err)
				}
			}
			key = pair.key
			keyFound = true
		case identValidateKey{}:
			validateKey = option.MustGet[bool](opt)
		case identKeyUsed{}:
			keyUsed = option.MustGet[*any](opt)
		case identCritValidation{}:
			critValidation = option.MustGet[bool](opt)
		case identCritExtension{}:
			criticalExtensions = append(criticalExtensions, option.MustGet[[]string](opt)...)
		case identBase64Encoder{}:
			return makeVerifyError(`jws.WithBase64Encoder() is not supported by VerifyDetachedReader; the streaming payload path uses RawURLEncoding`)
		case identSerialization{}:
			v := option.MustGet[int](opt)
			switch v {
			case fmtCompact:
				format = fmtCompact
			case fmtJSON, fmtJSONPretty:
				format = fmtJSON
			default:
				return makeVerifyError(`invalid serialization format value %d`, v)
			}
		case identKeyProvider{}, identDetachedPayload{}, identMessage{}:
			return makeVerifyError(`option %T is not supported by VerifyDetachedReader; use jws.Verify with jws.WithDetachedPayload() for the general detached path`, opt)
		default:
			return makeVerifyError(`invalid jws.VerifyOption %q passed`, `With`+strings.TrimPrefix(fmt.Sprintf(`%T`, opt.Ident()), `jws.ident`))
		}
	}

	if !keyFound {
		return makeVerifyError(`jws.WithKey() must be specified for VerifyDetachedReader`)
	}
	if alg == jwa.NoSignature() {
		return makeVerifyError(`"none" (jwa.NoSignature) cannot be used with VerifyDetachedReader; use jws.Parse if you need to inspect an unsecured JWS`)
	}

	detected := detectDetachedReaderFormat(src)
	if detected == 0 {
		return makeVerifyError(`input is empty or whitespace-only`)
	}
	if format == 0 {
		format = detected
	} else if format != detected {
		return makeVerifyError(`input format mismatch: %s specified but input appears to be %s`, detachedReaderFormatName(format), detachedReaderFormatName(detected))
	}

	if validateKey {
		if err := validateKeyBeforeUse(key); err != nil {
			return makeVerifyError(`failed to validate key: %w`, err)
		}
	}

	dsigAlg := resolveDetachedDsigAlgorithm(alg.String())
	dsigInfo, ok := dsig.GetAlgorithmInfo(dsigAlg)
	if !ok {
		return makeVerifyError(`unsupported algorithm %q; use jws.Verify with jws.WithDetachedPayload() if you need the general detached path`, alg)
	}
	switch dsigInfo.Family {
	case dsig.EdDSAFamily:
		return makeVerifyError(`algorithm %q does not support VerifyDetachedReader because it requires the full payload; use jws.Verify with jws.WithDetachedPayload() if the payload fits in memory`, alg)
	case dsig.Custom:
		return makeVerifyError(`custom algorithms do not support VerifyDetachedReader; use jws.Verify with jws.WithDetachedPayload() if the payload fits in memory`)
	}

	rawKey, err := convertKeyForDetachedVerify(key, dsigInfo.Family)
	if err != nil {
		return makeVerifyError(`failed to convert key: %w`, err)
	}

	protectedB64, decodedSig, err := extractDetachedReaderParts(src, format)
	if err != nil {
		return makeVerifyError(`%w`, err)
	}

	rawHeaders, err := base64.Decode(protectedB64)
	if err != nil {
		return makeVerifyError(`failed to decode protected header: %w`, err)
	}

	protected := NewHeaders()
	if err := json.Unmarshal(rawHeaders, protected); err != nil {
		return makeVerifyError(`failed to parse protected header: %w`, err)
	}
	if critValidation {
		if err := validateCritical(protected, criticalExtensions); err != nil {
			return makeVerifyError(`invalid "crit" header: %w`, err)
		}
	}

	hasher, err := createDetachedHasher(dsigInfo, rawKey)
	if err != nil {
		return makeVerifyError(`failed to create hasher: %w`, err)
	}
	if _, err := hasher.Write(protectedB64); err != nil {
		return makeVerifyError(`failed to write signing prefix: %w`, err)
	}
	if _, err := hasher.Write([]byte{tokens.Period}); err != nil {
		return makeVerifyError(`failed to write signing prefix: %w`, err)
	}
	if err := streamDetachedPayload(hasher, payload, getB64Value(protected)); err != nil {
		return makeVerifyError(`failed to stream payload: %w`, err)
	}
	if err := dsig.VerifyDigest(rawKey, dsigAlg, hasher.Sum(nil), decodedSig); err != nil {
		return makeVerifyError(`failed to verify signature: %w`, verificationError{err})
	}
	if keyUsed != nil {
		*keyUsed = key
	}
	return nil
}

type detachedJSONEnvelope struct {
	Header    json.RawMessage `json:"header,omitempty"`
	Protected string          `json:"protected"`
	Signature string          `json:"signature"`
}

func assembleDetachedJSON(public Headers, hdrEncoded, sigEncoded string, pretty bool) ([]byte, error) {
	env := detachedJSONEnvelope{
		Protected: hdrEncoded,
		Signature: sigEncoded,
	}
	if public != nil {
		hdrjs, err := json.Marshal(public)
		if err != nil {
			return nil, makeSignError(prefixJwsSignDetachedReader, `failed to marshal unprotected header: %w`, err)
		}
		env.Header = hdrjs
	}
	if pretty {
		out, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return nil, makeSignError(prefixJwsSignDetachedReader, `failed to marshal JSON output: %w`, err)
		}
		return out, nil
	}

	out, err := json.Marshal(env)
	if err != nil {
		return nil, makeSignError(prefixJwsSignDetachedReader, `failed to marshal JSON output: %w`, err)
	}
	return out, nil
}

func detectDetachedReaderFormat(src []byte) int {
	for _, b := range src {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case tokens.OpenCurlyBracket:
			return fmtJSON
		default:
			return fmtCompact
		}
	}
	return 0
}

func detachedReaderFormatName(f int) string {
	switch f {
	case fmtCompact:
		return `jws.WithCompact()`
	case fmtJSON, fmtJSONPretty:
		return `jws.WithJSON()`
	default:
		return fmt.Sprintf(`unknown(%d)`, f)
	}
}

func extractDetachedReaderParts(src []byte, format int) ([]byte, []byte, error) {
	switch format {
	case fmtCompact:
		protectedB64, payloadSegment, signatureSegment, err := jwsbb.SplitCompact(src)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to split compact: %w`, err)
		}
		if len(payloadSegment) != 0 {
			return nil, nil, fmt.Errorf(`compact input must have an empty payload segment for VerifyDetachedReader`)
		}
		decodedSig, err := base64.Decode(signatureSegment)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to decode signature: %w`, err)
		}
		return protectedB64, decodedSig, nil
	case fmtJSON, fmtJSONPretty:
		protectedB64, signatureB64, err := parseDetachedReaderJSON(src)
		if err != nil {
			return nil, nil, err
		}
		decodedSig, err := base64.Decode(signatureB64)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to decode signature: %w`, err)
		}
		return protectedB64, decodedSig, nil
	default:
		return nil, nil, fmt.Errorf(`unexpected serialization format %d`, format)
	}
}

type detachedReaderJSONProbe struct {
	Payload    *string           `json:"payload,omitempty"`
	Protected  *string           `json:"protected,omitempty"`
	Header     json.RawMessage   `json:"header,omitempty"`
	Signature  *string           `json:"signature,omitempty"`
	Signatures []json.RawMessage `json:"signatures,omitempty"`
}

type detachedReaderJSONSignatureProbe struct {
	Protected *string         `json:"protected,omitempty"`
	Header    json.RawMessage `json:"header,omitempty"`
	Signature *string         `json:"signature,omitempty"`
}

func parseDetachedReaderJSON(src []byte) ([]byte, []byte, error) {
	var probe detachedReaderJSONProbe
	if err := json.Unmarshal(src, &probe); err != nil {
		return nil, nil, fmt.Errorf(`failed to parse JSON serialization: %w`, err)
	}
	if probe.Payload != nil && *probe.Payload != "" {
		return nil, nil, fmt.Errorf(`JSON input must have an omitted or empty "payload" member for VerifyDetachedReader`)
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
		var sig detachedReaderJSONSignatureProbe
		if err := json.Unmarshal(probe.Signatures[0], &sig); err != nil {
			return nil, nil, fmt.Errorf(`failed to parse signatures[0]: %w`, err)
		}
		protectedB64 = sig.Protected
		signatureB64 = sig.Signature
	case len(probe.Signatures) > 1:
		return nil, nil, fmt.Errorf(`VerifyDetachedReader supports only single-signature JSON input, got %d`, len(probe.Signatures))
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

func cloneOrNewHeaders(hdr Headers) (Headers, error) {
	if hdr == nil {
		return NewHeaders(), nil
	}
	return hdr.Clone()
}

func resolveDetachedDsigAlgorithm(jwsAlg string) string {
	switch jwsAlg {
	case "HS256":
		return dsig.HMACWithSHA256
	case "HS384":
		return dsig.HMACWithSHA384
	case "HS512":
		return dsig.HMACWithSHA512
	case "RS256":
		return dsig.RSAPKCS1v15WithSHA256
	case "RS384":
		return dsig.RSAPKCS1v15WithSHA384
	case "RS512":
		return dsig.RSAPKCS1v15WithSHA512
	case "PS256":
		return dsig.RSAPSSWithSHA256
	case "PS384":
		return dsig.RSAPSSWithSHA384
	case "PS512":
		return dsig.RSAPSSWithSHA512
	case "ES256":
		return dsig.ECDSAWithP256AndSHA256
	case "ES384":
		return dsig.ECDSAWithP384AndSHA384
	case "ES512":
		return dsig.ECDSAWithP521AndSHA512
	case "EdDSA", "Ed25519":
		return dsig.EdDSA
	default:
		return jwsAlg
	}
}

func createDetachedHasher(info dsig.AlgorithmInfo, key any) (hash.Hash, error) {
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
		return nil, fmt.Errorf(`unsupported algorithm family %q for detached reader APIs`, info.Family)
	}
}

func writeDetachedPrefix(hasher hash.Hash, hdrbuf []byte, encoder Base64Encoder) error {
	if _, err := hasher.Write([]byte(encoder.EncodeToString(hdrbuf))); err != nil {
		return err
	}
	_, err := hasher.Write([]byte{tokens.Period})
	return err
}

func streamDetachedPayload(hasher hash.Hash, payload io.Reader, encodePayload bool) error {
	if !encodePayload {
		if _, err := io.Copy(hasher, payload); err != nil {
			return fmt.Errorf(`failed to stream payload: %w`, err)
		}
		return nil
	}

	w := stdbase64.NewEncoder(stdbase64.RawURLEncoding, hasher)
	if _, err := io.Copy(w, payload); err != nil {
		_ = w.Close()
		return fmt.Errorf(`failed to stream payload through base64 encoder: %w`, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf(`failed to close base64 encoder: %w`, err)
	}
	return nil
}

func convertKeyForDetachedSign(key any, family dsig.Family) (any, error) {
	if _, ok := key.(jwk.Key); !ok {
		return key, nil
	}

	switch family {
	case dsig.HMAC:
		return keyconv.KeyAs[[]byte](key)
	case dsig.RSA:
		return keyconv.KeyAs[*rsa.PrivateKey](key)
	case dsig.ECDSA:
		return keyconv.KeyAs[*ecdsa.PrivateKey](key)
	default:
		return key, nil
	}
}

func convertKeyForDetachedVerify(key any, family dsig.Family) (any, error) {
	if _, ok := key.(jwk.Key); !ok {
		return key, nil
	}

	switch family {
	case dsig.HMAC:
		return keyconv.KeyAs[[]byte](key)
	case dsig.RSA:
		return keyconv.RSAPublicKey(key)
	case dsig.ECDSA:
		return keyconv.ECDSAPublicKey(key)
	default:
		return key, nil
	}
}
