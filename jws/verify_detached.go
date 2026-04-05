package jws

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"hash"
	"io"

	"github.com/lestrrat-go/dsig"
	internbase64 "github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

// VerifyDetached verifies a JWS compact serialization against a detached
// payload provided as an io.Reader. Unlike jws.Verify with
// jws.WithDetachedPayload, this function never materializes the payload
// in memory — it streams the payload through the hash function used by
// the signature algorithm.
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
// The compact parameter must be a JWS compact serialization with an
// empty payload segment (detached).
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
	var encoder Base64Encoder = internbase64.DefaultEncoder()

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
		case identBase64Encoder{}:
			if err := option.Value(&encoder); err != nil {
				return makeVerifyError(`failed to retrieve base64-encoder option value: %w`, err)
			}
		case identKeyProvider{}, identDetachedPayload{}, identMessage{}, identSerialization{}:
			return makeVerifyError(`option %T is not supported by VerifyDetached; use jws.WithKey() to specify a single key`, option)
		}
	}

	if !keyFound {
		return makeVerifyError(`jws.WithKey() must be specified for VerifyDetached`)
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

	// Parse the compact token — header and signature are small
	protected, payloadSegment, signatureSegment, err := jwsbb.SplitCompact(compact)
	if err != nil {
		return makeVerifyError(`failed to split compact: %w`, err)
	}

	if len(payloadSegment) != 0 {
		return makeVerifyError(`compact token must have an empty payload segment for VerifyDetached`)
	}

	// Decode the protected header
	rawHeaders, err := internbase64.Decode(protected)
	if err != nil {
		return makeVerifyError(`failed to decode protected header: %w`, err)
	}

	// Parse the header to get b64
	hdr := NewHeaders()
	if err := json.Unmarshal(rawHeaders, hdr); err != nil {
		return makeVerifyError(`failed to parse protected header: %w`, err)
	}

	encodePayload := getB64Value(hdr)

	// Decode the signature
	decodedSig, err := internbase64.Decode(signatureSegment)
	if err != nil {
		return makeVerifyError(`failed to decode signature: %w`, err)
	}

	// Create the hasher
	hasher, err := createHasher(dsigInfo, rawKey)
	if err != nil {
		return makeVerifyError(`failed to create hasher: %w`, err)
	}

	// Build the signing prefix: base64url(header) + "."
	signingPrefix := jwsbb.SigningPrefix(nil, rawHeaders, encoder)

	if _, err := hasher.Write(signingPrefix); err != nil {
		return makeVerifyError(`failed to write signing prefix: %w`, err)
	}

	if err := streamPayload(hasher, payload, encodePayload); err != nil {
		return makeVerifyError(`failed to stream payload: %w`, err)
	}

	digest := hasher.Sum(nil)

	if err := dsig.VerifyDigest(rawKey, dsigAlg, digest, decodedSig); err != nil {
		return makeVerifyError(`failed to verify signature: %w`, verificationError{err})
	}

	return nil
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
