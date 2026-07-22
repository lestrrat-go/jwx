//go:generate ../scripts/jwxcodegen.sh generate-headers -objects=objects.yml

// Package jws implements the digital signature on JSON based data
// structures as described in https://tools.ietf.org/html/rfc7515
//
// If you do not care about the details, the only things that you
// would need to use are the following functions:
//
//	jws.Sign(payload, jws.WithKey(algorithm, key))
//	jws.Verify(serialized, jws.WithKey(algorithm, key))
//
// To sign, simply use `jws.Sign`. `payload` is a []byte buffer that
// contains whatever data you want to sign. `alg` is one of the
// jwa.SignatureAlgorithm constants from package jwa. For RSA and
// ECDSA family of algorithms, you will need to prepare a private key.
// For HMAC family, you just need a []byte value. The `jws.Sign`
// function will return the encoded JWS message on success.
//
// To verify, use `jws.Verify`. It will parse the `encodedjws` buffer
// and verify the result using `algorithm` and `key`. Upon successful
// verification, the original payload is returned, so you can work on it.
//
// `jws.Sign()` and `jws.Verify()` are the default general-purpose entry
// points. For detached payloads already available as `[]byte`, pass
// `jws.WithDetachedPayload()`. For detached payloads that should be
// streamed from an `io.Reader` without materializing them in memory, pass
// `jws.WithDetachedPayloadReader()`. The streaming path is intentionally
// narrower — single key, detached only, HMAC/RSA/ECDSA only.
//
// As a sidenote, consider using github.com/lestrrat-go/htmsig if you
// looking for HTTP Message Signatures (RFC9421) -- it uses the same
// underlying signing/verification mechanisms as this module.
package jws

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"github.com/lestrrat-go/option/v3"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	jwsbbi "github.com/lestrrat-go/jwx/v4/jws/internal/jwsbb"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

var registry = json.NewRegistry()

var maxSignatures atomic.Int64

func init() {
	maxSignatures.Store(100)
}

type defaultSigner struct {
	alg jwa.SignatureAlgorithm
}

func (s defaultSigner) Sign(key any, payload []byte) ([]byte, error) {
	return jwsbb.Sign(key, s.alg.String(), payload, nil)
}

const (
	fmtInvalid = 1 << iota
	fmtCompact
	fmtJSON
	fmtJSONPretty
	fmtMax
)

func validateKeyBeforeUse(key any) error {
	jwkKey, ok := key.(jwk.Key)
	if !ok {
		converted, err := jwk.Import[jwk.Key](key)
		if err != nil {
			return fmt.Errorf(`could not convert key of type %T to jwk.Key for validation: %w`, key, err)
		}
		jwkKey = converted
	}
	return jwkKey.Validate()
}

// Sign generates a JWS message for the given payload and returns
// it in serialized form, which can be in either compact or
// JSON format. Default is compact.
//
// You must pass at least one key to `jws.Sign()` by using `jws.WithKey()`
// option.
//
//	jws.Sign(payload, jws.WithKey(alg, key))
//	jws.Sign(payload, jws.WithJSON(), jws.WithKey(alg1, key1), jws.WithKey(alg2, key2))
//
// Note that in the second example the `jws.WithJSON()` option is
// specified as well. This is because the compact serialization
// format does not support multiple signatures, and users must
// specifically ask for the JSON serialization format.
//
// Read the documentation for `jws.WithKey()` to learn more about the
// possible values that can be used for `alg` and `key`.
//
// You may create JWS messages with the "none" (jwa.NoSignature) algorithm
// if you use the `jws.WithInsecureNoSignature()` option. This option
// can be combined with one or more signature keys, as well as the
// `jws.WithJSON()` option to generate multiple signatures (though
// the usefulness of such constructs is highly debatable)
//
// Note that this library does not allow you to successfully call `jws.Verify()` on
// signatures with the "none" algorithm. To parse these, use `jws.Parse()` instead.
//
// If you want to use a detached payload, use `jws.WithDetachedPayload()` as
// one of the options. When you use this option, you must always set the
// first parameter (`payload`) to `nil`, or the function will return an error
//
// You may also want to look at how to pass protected headers to the
// signing process, as you will likely be required to set the `b64` field
// when using detached payload.
//
// RFC 7797 note: producing an in-band compact JWS with `b64=false`
// (i.e. setting the `b64` protected header to `false` without also
// passing [WithDetachedPayload]) is "NOT RECOMMENDED" per §5.2; strict
// peers commonly reject such messages. The canonical pairing for
// `b64=false` is [WithDetachedPayload] (or [WithDetachedPayloadReader]
// for streaming), which keeps the unencoded payload out of the wire
// format. Sign auto-declares `"b64"` in `crit` whenever `b64=false`
// is set, so the produced JWS is at least RFC 7797 §3 conformant on
// the producer side.
//
// Look for options that return `jws.SignOption` or `jws.SignVerifyOption`
// for a complete list of options that can be passed to this function.
//
// You can use `errors.Is` with `jws.SignError()` to check if an error is from this function.
func Sign(payload []byte, options ...SignOption) ([]byte, error) {
	sc := signContextPool.Get()
	defer signContextPool.Put(sc)

	sc.payload = payload

	if err := sc.ProcessOptions(options); err != nil {
		return nil, makeSignError(prefixJwsSign, `failed to process options: %w`, err)
	}

	lsigner := len(sc.sigbuilders)
	if lsigner == 0 {
		return nil, makeSignError(prefixJwsSign, `no signers available. Specify an algorithm and a key using jws.WithKey()`)
	}

	// Design note: while we could have easily set format = fmtJSON when
	// lsigner > 1, I believe the decision to change serialization formats
	// must be explicitly stated by the caller. Otherwise, I'm pretty sure
	// there would be people filing issues saying "I get JSON when I expected
	// compact serialization".
	//
	// Therefore, instead of making implicit format conversions, we force the
	// user to spell it out as `jws.Sign(..., jws.WithJSON(), jws.WithKey(...), jws.WithKey(...))`
	if sc.format == fmtCompact && lsigner != 1 {
		return nil, makeSignError(prefixJwsSign, `cannot have multiple signers (keys) specified for compact serialization. Use only one jws.WithKey()`)
	}

	if sc.payloadReader != nil {
		return sc.signStreaming()
	}

	// For compact single-signature (the overwhelmingly common case),
	// bypass Message construction and Compact() entirely.
	// Build() returns the signing input buffer (base64(hdr).base64(payload))
	// so we can append the signature directly without re-encoding.
	if sc.format == fmtCompact {
		sb := sc.sigbuilders[0]
		if sc.validateKey {
			if err := validateKeyBeforeUse(sb.key); err != nil {
				return nil, makeSignError(prefixJwsSign, `failed to validate key for signature: %w`, err)
			}
		}

		br, err := sb.Build(sc, sc.payload)
		if err != nil {
			return nil, makeSignError(prefixJwsSign, `failed to build signature: %w`, err)
		}

		if sc.detached {
			// Detached: output is base64(hdr)..base64(sig) (empty payload segment).
			// The combined buffer is base64(hdr).base64(payload), so slice
			// up to and including the period to get base64(hdr). and append
			// the signature after that.
			idx := bytes.IndexByte(br.combined, '.')
			result := jwsbb.AppendSignature(br.combined[:idx+1], br.sig.signature, sc.encoder)
			return result, nil
		}

		// Non-detached: append .base64(sig) to the existing signing buffer.
		result := jwsbb.AppendSignature(br.combined, br.sig.signature, sc.encoder)
		return result, nil
	}

	// JSON serialization path - needs full Message construction
	var result Message

	if err := sc.PopulateMessage(&result); err != nil {
		return nil, makeSignError(prefixJwsSign, `failed to populate message: %w`, err)
	}
	switch sc.format {
	case fmtJSON:
		return json.Marshal(result)
	case fmtJSONPretty:
		return json.MarshalIndent(result, "", "  ")
	default:
		return nil, makeSignError(prefixJwsSign, `invalid serialization format`)
	}
}

// Verify checks if the given JWS message is verifiable using `alg` and `key`.
// `key` may be a "raw" key (e.g. rsa.PublicKey) or a jwk.Key
//
// If the verification is successful, `err` is nil, and the content of the
// payload that was signed is returned. If you need more fine-grained
// control of the verification process, manually generate a
// `Verifier` in `verify` subpackage, and call `Verify` method on it.
// If you need to access signatures and JOSE headers in a JWS message,
// use `Parse` function to get `Message` object.
//
// Because the use of "none" (jwa.NoSignature) algorithm is strongly discouraged,
// this function DOES NOT consider it a success when `{"alg":"none"}` is
// encountered in the message (it would also be counterintuitive when the code says
// it _verified_ something when in fact it did no such thing). If you want to
// accept messages with "none" signature algorithm, use `jws.Parse` to get the
// raw JWS message.
//
// By default, Verify rejects a JWS whose protected header "alg" does not
// exactly equal the algorithm actually used to verify it. The verification
// algorithm is resolved from the key or provider you supply (jws.WithKey,
// jws.WithKeySet, jws.WithVerifyAuto, or a custom jws.WithKeyProvider); if the
// protected header advertises a different "alg", verification fails even when
// the signature would otherwise be cryptographically valid. The match is plain
// string equality, with no aliasing: the deprecated polymorphic "EdDSA" and the
// fully-specified "Ed25519"/"Ed448" identifiers are distinct per RFC 9864 and
// are not interchangeable. This check fires only when the protected header
// carries an "alg" — messages that place "alg" only in the unprotected header
// (or omit it) are unaffected. Pass jws.WithSkipAlgorithmMatch(true) to bypass
// the check for non-conforming producers. The compact fast path
// [VerifyCompactFast] performs an equivalent cross-check against its explicitly
// supplied algorithm.
//
// The error returned by this function is of type can be checked against
// `jws.VerifyError()` and `jws.VerificationError()`. The latter is returned
// when the verification process itself fails (e.g. invalid signature, wrong key),
// while the former is returned when any other part of the `jws.Verify()`
// function fails.
//
// When `jws.WithDetachedPayloadReader()` is used, the payload is streamed
// from the caller's `io.Reader` and is not extracted from the JWS envelope.
// In that case, the returned `[]byte` is a non-nil zero-length slice on
// success; the verified bytes are whatever the caller read from the Reader.
// Do not treat the returned slice as "the payload is empty" — callers that
// need the payload bytes must retain their own copy.
//
// Context cancellation is governed by [WithContext]. The slow-path verify
// loop checks ctx.Err() between each signature, each key provider, and
// each (alg, key) attempt; jkuProvider passes ctx to its underlying
// jwk.Fetcher; the streaming path checks ctx between payload Reads.
// staticKeyProvider and keySetProvider do not consult ctx inside
// FetchKeys themselves (their backing data is already in memory) — see
// the [WithContext] godoc for the full per-layer breakdown.
func Verify(buf []byte, options ...VerifyOption) ([]byte, error) {
	vc := verifyContextPool.Get()
	defer verifyContextPool.Put(vc)

	if err := vc.ProcessOptions(options); err != nil {
		return nil, makeVerifyError(`failed to process options: %w`, err)
	}

	return vc.VerifyMessage(buf)
}

// getB64Value reads the typed "b64" header field and returns its value,
// or RFC 7797's default of true when the field is unset. The field is
// declared in jws/objects.yml as a typed bool, so Set rejects non-bool
// values at the API boundary; this helper exists so callers do not have
// to write the same nil-default check at every read site.
func getB64Value(hdr Headers) bool {
	v, ok := hdr.B64()
	if !ok {
		return true // RFC 7797 default
	}
	return v
}

// detectParseFormat inspects the first non-whitespace rune in src to
// classify the input as compact or JSON serialization. Returns 0 on
// empty or whitespace-only input so callers can distinguish "no usable
// bytes" from a successful classification.
func detectParseFormat(src []byte) int {
	for i := 0; i < len(src); {
		r := rune(src[i])
		width := 1
		if r >= utf8.RuneSelf {
			r, width = utf8.DecodeRune(src[i:])
		}
		if !unicode.IsSpace(r) {
			if r == tokens.OpenCurlyBracket {
				return fmtJSON
			}
			return fmtCompact
		}
		i += width
	}
	return 0
}

// Parse parses contents from the given source and creates a jws.Message
// struct. By default the input can be in either compact or full JSON serialization.
//
// You may pass `jws.WithJSON()` and/or `jws.WithCompact()` to specify
// explicitly which format to use. If neither or both is specified, the function
// will attempt to autodetect the format. If one or the other is specified,
// only the specified format will be attempted.
//
// Bounding the input size is the caller's responsibility; this function
// trusts the caller-provided src. See docs/13-input-size.md.
//
// On error, returns a jws.ParseError.
func Parse(src []byte, options ...ParseOption) (*Message, error) {
	maxSigs := int(maxSignatures.Load())

	var formats int
	for _, opt := range options {
		switch opt.Ident() {
		case identSerialization{}:
			v := option.MustGet[int](opt)
			switch v {
			case fmtJSON:
				formats |= fmtJSON
			case fmtCompact:
				formats |= fmtCompact
			}
		case identMaxSignatures{}:
			maxSigs = option.MustGet[int](opt)
			if maxSigs <= 0 {
				return nil, makeParseError(`jws.Parse`, `WithMaxSignatures must be greater than zero`)
			}
		}
	}

	// if format is 0 or both JSON/Compact, auto detect
	if v := formats & (fmtJSON | fmtCompact); v == 0 || v == fmtJSON|fmtCompact {
		formats = detectParseFormat(src)
	}

	if formats&fmtCompact == fmtCompact {
		msg, err := parseCompact(src)
		if err != nil {
			return nil, makeParseError(`jws.Parse`, `failed to parse compact format: %w`, err)
		}
		return msg, nil
	} else if formats&fmtJSON == fmtJSON {
		msg, err := parseJSON(src, maxSigs)
		if err != nil {
			return nil, makeParseError(`jws.Parse`, `failed to parse JSON format: %w`, err)
		}
		return msg, nil
	}

	return nil, makeParseError(`jws.Parse`, `invalid byte sequence`)
}

// ParseString parses contents from the given source and creates a jws.Message
// struct. The input can be in either compact or full JSON serialization.
//
// On error, returns a jws.ParseError.
func ParseString(src string, options ...ParseOption) (*Message, error) {
	msg, err := Parse([]byte(src), options...)
	if err != nil {
		return nil, makeParseError(`jws.ParseString`, `failed to parse string: %w`, err)
	}
	return msg, nil
}

// ParseReader parses contents from the given source and creates a jws.Message
// struct. The input can be in either compact or full JSON serialization.
//
// Bounding the input size is the caller's responsibility: wrap src with
// [io.LimitReader] or [net/http.MaxBytesReader] before passing it in. See
// docs/13-input-size.md for the rationale.
//
// On error, returns a jws.ParseError.
func ParseReader(src io.Reader, options ...ParseOption) (*Message, error) {
	buf, err := io.ReadAll(src)
	if err != nil {
		return nil, makeParseError(`jws.ParseReader`, `failed to read from io.Reader: %w`, err)
	}
	return Parse(buf, options...)
}

func parseJSON(data []byte, maxSigs int) (result *Message, err error) {
	var m Message
	m.maxSignatures = maxSigs
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf(`failed to unmarshal jws message: %w`, err)
	}
	return &m, nil
}

func parseCompact(data []byte) (m *Message, err error) {
	protected, payload, signature, err := jwsbb.SplitCompact(data)
	if err != nil {
		return nil, makeParseError(`jws.Parse`, `invalid compact serialization format: %w`, err)
	}
	return parse(protected, payload, signature)
}

func parse(protected, payload, signature []byte) (*Message, error) {
	decodedHeader, err := base64.Decode(protected)
	if err != nil {
		return nil, fmt.Errorf(`failed to decode protected headers: %w`, err)
	}

	hdr := NewHeaders()
	if err := json.Unmarshal(decodedHeader, hdr); err != nil {
		return nil, fmt.Errorf(`failed to parse JOSE headers: %w`, err)
	}

	var decodedPayload []byte
	b64 := getB64Value(hdr)
	if !b64 {
		decodedPayload = payload
	} else {
		v, err := base64.Decode(payload)
		if err != nil {
			return nil, fmt.Errorf(`failed to decode payload: %w`, err)
		}
		decodedPayload = v
	}

	// The payload decode above and the signature decode below intentionally use
	// the auto-detecting base64 decoder, which tolerates non-standard variants
	// (e.g. padded base64url, standard base64) in addition to RFC 7515's raw
	// base64url. This leniency is deliberate: jws.Verify is the interop path,
	// whereas VerifyCompactFast strictly decodes the payload and signature
	// (RFC 4648 §5 raw base64url, no padding) and its godoc directs callers whose
	// JWS uses non-standard encoding to use jws.Verify instead. The cost is that
	// serialized-JWS strings are
	// non-canonical/malleable (a signature re-encoded in a different base64
	// variant decodes to the same bytes but yields a different compact string).
	// This does NOT affect signature validity or enable forgery; it only matters
	// to systems that key replay/dedup on the raw compact-JWS string, which should
	// instead key on the verified payload/claims. This is a deliberate won't-fix:
	// do NOT switch this to strict decoding; callers needing strict raw base64url
	// decoding of the payload and signature should use VerifyCompactFast.
	decodedSignature, err := base64.Decode(signature)
	if err != nil {
		return nil, fmt.Errorf(`failed to decode signature: %w`, err)
	}
	if len(decodedSignature) == 0 {
		alg, ok := hdr.Algorithm()
		if !ok || alg != jwa.NoSignature() {
			return nil, fmt.Errorf(`empty compact signature requires protected header "alg" to be "none"`)
		}
	}

	var msg Message
	msg.payload = decodedPayload
	// Compact serialization has no way to express "present but empty":
	// an empty middle segment is genuinely absent (detached). Presence is
	// therefore simply whether the middle segment carried any bytes.
	msg.payloadPresent = len(payload) > 0
	msg.signatures = append(msg.signatures, &Signature{
		protected: hdr,
		signature: decodedSignature,
	})
	msg.b64 = b64
	return &msg, nil
}

// CustomDecoder is a generic interface for custom field decoders.
type CustomDecoder[T any] = json.CustomDecoder[T]

// CustomDecodeFunc is a function-based implementation of CustomDecoder[T].
type CustomDecodeFunc[T any] = json.CustomDecodeFunc[T]

// RegisterCustomField registers a private field to be decoded as type T
// using json.Unmarshal. This option has a global effect.
//
//	jws.RegisterCustomField[time.Time](`x-birthday`)
//
// For more fine-tuned control over the decoding process,
// use RegisterCustomDecoder instead.
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterCustomField[T any](name string) error {
	json.RegisterTyped[T](registry, name)
	return nil
}

// RegisterCustomDecoder registers a private field with a custom decoder
// function. This option has a global effect.
//
//	jws.RegisterCustomDecoder(`x-birthday`, jws.CustomDecodeFunc[time.Time](func(data []byte) (time.Time, error) {
//	  var s string
//	  if err := json.Unmarshal(data, &s); err != nil {
//	    return time.Time{}, err
//	  }
//	  return time.Parse(time.RFC1123, s)
//	}))
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterCustomDecoder[T any](name string, dec CustomDecodeFunc[T]) error {
	json.RegisterCustomDecoder[T](registry, name, dec)
	return nil
}

// UnregisterCustomField removes the registration for a custom field.
//
// The error return is reserved for future validation (for example,
// refusing to unregister a built-in field) and is always nil today.
// Callers — especially extension modules scripting Register/Unregister
// cycles from init() — should check the returned value and propagate
// on failure to stay forward-compatible, matching the convention on
// [RegisterCustomField] / [RegisterCustomDecoder].
func UnregisterCustomField(name string) error {
	registry.Unregister(name)
	return nil
}

// Helpers for signature verification
var muAlgorithmMaps sync.RWMutex
var keyTypeToAlgorithms = make(map[jwa.KeyType][]jwa.SignatureAlgorithm)
var algorithmToKeyTypes = make(map[jwa.SignatureAlgorithm][]jwa.KeyType)
var curveToAlgorithms = make(map[jwa.EllipticCurveAlgorithm][]jwa.SignatureAlgorithm)

func init() {
	mustRegisterAlgorithmForKeyType(jwa.OKP(), jwa.EdDSA())
	mustRegisterAlgorithmForCurve(jwa.Ed25519(), jwa.EdDSAEd25519())
	for _, alg := range []jwa.SignatureAlgorithm{jwa.HS256(), jwa.HS384(), jwa.HS512()} {
		mustRegisterAlgorithmForKeyType(jwa.OctetSeq(), alg)
	}
	for _, alg := range []jwa.SignatureAlgorithm{jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512()} {
		mustRegisterAlgorithmForKeyType(jwa.RSA(), alg)
	}
	for _, alg := range []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()} {
		mustRegisterAlgorithmForKeyType(jwa.EC(), alg)
	}
}

func mustRegisterAlgorithmForKeyType(kty jwa.KeyType, alg jwa.SignatureAlgorithm) {
	if err := RegisterAlgorithmForKeyType(kty, alg); err != nil {
		panic(fmt.Sprintf("jws: failed to register builtin algorithm for key type: %s", err))
	}
}

func mustRegisterAlgorithmForCurve(crv jwa.EllipticCurveAlgorithm, alg jwa.SignatureAlgorithm) {
	if err := RegisterAlgorithmForCurve(crv, alg); err != nil {
		panic(fmt.Sprintf("jws: failed to register builtin algorithm for curve: %s", err))
	}
}

// RegisterAlgorithmForKeyType registers an additional algorithm as valid for
// the given key type. This is used internally by init() and can also be called
// from external modules that provide support for additional algorithms (e.g. Ed448).
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterAlgorithmForKeyType(kty jwa.KeyType, alg jwa.SignatureAlgorithm) error {
	muAlgorithmMaps.Lock()
	defer muAlgorithmMaps.Unlock()
	keyTypeToAlgorithms[kty] = append(keyTypeToAlgorithms[kty], alg)
	if !slices.Contains(algorithmToKeyTypes[alg], kty) {
		algorithmToKeyTypes[alg] = append(algorithmToKeyTypes[alg], kty)
	}
	return nil
}

// RegisterAlgorithmForCurve registers an algorithm as valid for the given
// elliptic curve. When [AlgorithmsForKey] can determine the curve of a key,
// it returns the union of key-type-level algorithms and curve-specific
// algorithms instead of all algorithms for the key type.
//
// This function is append-only and deduplicates entries, so builtin
// registrations cannot be overwritten by external modules.
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterAlgorithmForCurve(crv jwa.EllipticCurveAlgorithm, alg jwa.SignatureAlgorithm) error {
	muAlgorithmMaps.Lock()
	defer muAlgorithmMaps.Unlock()
	if slices.Contains(curveToAlgorithms[crv], alg) {
		return nil
	}
	curveToAlgorithms[crv] = append(curveToAlgorithms[crv], alg)
	return nil
}

// AlgorithmsForKey returns the possible signature algorithms that can
// be used for a given key. It only takes in consideration keys/algorithms
// for verification purposes, as this is the only usage where one may need
// dynamically figure out which method to use.
//
// When the key's curve can be determined (via [jwk.Key] Crv() method or
// inferred from the raw Go type), curve-specific algorithms registered via
// [RegisterAlgorithmForCurve] are combined with key-type-level algorithms
// to produce a more precise result.
//
// Accepted key shapes (resolved in order):
//
//  1. [jwk.Key] — kty is read directly; if the implementation also exposes
//     Crv(), the curve refines the result.
//  2. Stdlib crypto types: [rsa.PublicKey] / [rsa.PrivateKey] (and pointer
//     forms), [ecdsa.PublicKey] / [ecdsa.PrivateKey] (and pointer forms),
//     [ed25519.PublicKey], [ed25519.PrivateKey], and [byte] slices for
//     symmetric keys.
//  3. [crypto/ecdh.PublicKey] / [crypto/ecdh.PrivateKey] (and pointer
//     forms) — explicitly rejected; ECDH keys are key-agreement only.
//     Returns an error wrapping [ErrUnclassifiableKey].
//  4. [crypto.Signer] (e.g. KMS-backed adapters) — resolved once via
//     .Public(); the public key is then re-classified through tiers 1–2
//     or the [jwk.Import] fallback below. To prevent infinite recursion,
//     a Signer whose .Public() is itself a Signer is left for the
//     downstream dispatcher to handle.
//  5. [jwk.Import] fallback — anything else is offered to the import
//     registry, allowing extension modules to register their own raw key
//     types.
//
// All "we cannot classify this key" failures wrap [ErrUnclassifiableKey],
// so callers can branch with errors.Is rather than pattern-matching error
// strings. The wrapping error keeps the concrete %T or %q diagnostic in
// its message for human readers.
func AlgorithmsForKey(key any) ([]jwa.SignatureAlgorithm, error) {
	var kty jwa.KeyType
	var crv jwa.EllipticCurveAlgorithm
	var hasCrv bool

	switch key := key.(type) {
	case jwk.Key:
		kty = key.KeyType()
		type curver interface {
			Crv() (jwa.EllipticCurveAlgorithm, bool)
		}
		if ck, ok := key.(curver); ok {
			crv, hasCrv = ck.Crv()
		}
	case rsa.PublicKey, *rsa.PublicKey, rsa.PrivateKey, *rsa.PrivateKey:
		kty = jwa.RSA()
	case ecdsa.PublicKey, *ecdsa.PublicKey, ecdsa.PrivateKey, *ecdsa.PrivateKey:
		kty = jwa.EC()
	case ed25519.PublicKey, ed25519.PrivateKey:
		// AlgorithmsForKey classifies by key type to report which algorithms a
		// key *could* be used with; it is not a key validator. Value-form
		// ed25519 keys are []byte aliases with no length invariant, so a
		// wrong-length key is intentionally NOT rejected here — it would still
		// be reported as [EdDSA Ed25519]. Key validity (correct length) is
		// enforced where it matters, at Sign/Verify time. Do NOT add a length
		// check to this advisory classifier.
		kty = jwa.OKP()
		crv = jwa.Ed25519()
		hasCrv = true
	case *ed25519.PublicKey, *ed25519.PrivateKey:
		// Pointer-form ed25519 keys satisfy crypto.Signer, so without an
		// explicit case here a typed-nil or wrong-length pointer would
		// fall through to the default branch and panic inside
		// signer.Public(). Validate length/nil up front instead.
		if err := validateEd25519KeyShape(key); err != nil {
			return nil, fmt.Errorf(`%w: %w`, errUnclassifiableKey, err)
		}
		kty = jwa.OKP()
		crv = jwa.Ed25519()
		hasCrv = true
	case *ecdh.PublicKey, ecdh.PublicKey, *ecdh.PrivateKey, ecdh.PrivateKey:
		// ecdh keys are for key agreement (X25519/X448), not signing.
		// Reject at the API boundary instead of returning a misleading
		// algorithm list that would fail deeper in the signing stack.
		return nil, fmt.Errorf(`%w: key type %T cannot be used for signing (ecdh keys are key-agreement only)`, errUnclassifiableKey, key)
	case []byte:
		kty = jwa.OctetSeq()
	default:
		// For crypto.Signer from external packages (e.g. KMS-backed signers),
		// extract the underlying public key type via .Public().
		// Standard library types (*rsa.PrivateKey, etc.) are already handled
		// by the concrete cases above.
		var signerPubErr error
		if signer, ok := key.(crypto.Signer); ok {
			pub := signer.Public()
			// A custom crypto.Signer may hand back a malformed (wrong-length or
			// typed-nil) ed25519.PublicKey. Classifying that as OKP would let it
			// reach the EdDSA verify path, which panics ("ed25519: bad public key
			// length"). Reject it here instead.
			if err := validateEd25519KeyShape(pub); err != nil {
				return nil, fmt.Errorf(`%w: %w`, errUnclassifiableKey, err)
			}
			// Guard: only recurse if the public key is not itself a crypto.Signer,
			// to prevent infinite recursion from pathological implementations.
			if _, isSigner := pub.(crypto.Signer); !isSigner {
				algs, err := AlgorithmsForKey(pub)
				if err == nil {
					return algs, nil
				}
				// Save the inner classification error so a
				// downstream Import-fallback failure can surface
				// both diagnostics. A successful Import discards
				// signerPubErr — only the eventual failure path
				// joins them.
				signerPubErr = err
			}
		}
		imported, err := jwk.Import[jwk.Key](key)
		if err != nil {
			outer := fmt.Errorf(`%w: unknown key type %T`, errUnclassifiableKey, key)
			if signerPubErr != nil {
				return nil, errors.Join(outer, signerPubErr)
			}
			return nil, outer
		}
		kty = imported.KeyType()
		type curver interface {
			Crv() (jwa.EllipticCurveAlgorithm, bool)
		}
		if ck, ok := imported.(curver); ok {
			crv, hasCrv = ck.Crv()
		}
	}

	muAlgorithmMaps.RLock()
	defer muAlgorithmMaps.RUnlock()

	ktyAlgs, ok := keyTypeToAlgorithms[kty]
	if !ok {
		return nil, fmt.Errorf(`%w: unregistered key type %q`, errUnclassifiableKey, kty)
	}

	// If we know the curve and there are curve-specific registrations,
	// return only key-type-level algorithms (those not registered under
	// any curve) plus curve-specific algorithms for this curve.
	if hasCrv {
		crvAlgs := curveToAlgorithms[crv]
		return filterAlgorithmsForCurve(ktyAlgs, crvAlgs), nil
	}

	return ktyAlgs, nil
}

// filterAlgorithmsForCurve returns the subset of ktyAlgs that are not
// registered under any curve (i.e., generic for the key type) plus the
// curve-specific algorithms from crvAlgs.
func filterAlgorithmsForCurve(ktyAlgs, crvAlgs []jwa.SignatureAlgorithm) []jwa.SignatureAlgorithm {
	var result []jwa.SignatureAlgorithm

	// Add key-type-level algorithms that are not claimed by any curve
	for _, alg := range ktyAlgs {
		if !isRegisteredUnderAnyCurve(alg) {
			result = append(result, alg)
		}
	}

	// Add curve-specific algorithms
	result = append(result, crvAlgs...)
	return result
}

func isRegisteredUnderAnyCurve(alg jwa.SignatureAlgorithm) bool {
	for _, algs := range curveToAlgorithms {
		if slices.Contains(algs, alg) {
			return true
		}
	}
	return false
}

// validateAlgorithmForKey checks that alg is compatible with key.
// Three classification failures are intentionally allowed through:
//
// (a) a nil key, used by keyless algorithms (see GH910);
// (b) any key handed to an algorithm with a user-registered custom
// [Signer] or [Verifier] — custom implementations may accept arbitrary
// key types that AlgorithmsForKey cannot classify;
// (c) an opaque crypto.Signer whose .Public() is itself a crypto.Signer,
// the one case AlgorithmsForKey refuses to recurse into.
//
// Every other classification failure is surfaced so callers get a crisp
// option-boundary rejection instead of a deep-stack error.
//
// A jwk.UnsupportedKey placeholder is rejected before any carve-out is
// considered: it carries no usable key material, so not even a custom
// Signer/Verifier may receive it.
//
// Carve-out (b) is OR-symmetric across the two registries: hasCustomSigVerifier
// checks both signerDB and verifierDB, so registering EITHER a custom Signer
// OR a custom Verifier loosens the gate for that alg on BOTH the sign and
// verify paths. Importing a verifier-only extension therefore also affects
// jws.Sign-path validation. This is intentional: downstream dispatchers in
// jws/jwsbb re-gate the key shape (via keyconv.KeyAs[T] or
// signer.Public().(*concrete)) before any cryptographic call, so a loose
// validateAlgorithmForKey verdict can only produce a deeper-stack
// type-mismatch error, never a forged signature.
func validateAlgorithmForKey(alg jwa.SignatureAlgorithm, key any) error {
	if key == nil {
		return nil
	}
	// A jwk.UnsupportedKey placeholder must never reach a Signer or
	// Verifier — including a custom-registered one, whose carve-out (b)
	// below would otherwise skip key classification entirely and hand
	// the placeholder to the callback as key material.
	if err := unsupportedKeyError(key, "signing or verification"); err != nil {
		return fmt.Errorf(`jws.WithKey: %w`, err)
	}
	algs, err := AlgorithmsForKey(key)
	if err != nil {
		if hasCustomSigVerifier(alg) {
			return nil
		}
		// A malformed ed25519 key (typed-nil or wrong-length, value or
		// pointer form) satisfies crypto.Signer but panics in Public().
		// Surface the classification error directly instead of probing it.
		if shapeErr := validateEd25519KeyShape(key); shapeErr != nil {
			return fmt.Errorf(`jws.WithKey: %w`, err)
		}
		if signer, ok := key.(crypto.Signer); ok {
			if _, isSigner := signer.Public().(crypto.Signer); isSigner {
				return nil
			}
		}
		return fmt.Errorf(`jws.WithKey: %w`, err)
	}
	if !slices.Contains(algs, alg) {
		if hasCustomSigVerifier(alg) {
			return nil
		}
		return fmt.Errorf(`jws.WithKey: algorithm %q is not compatible with key type %T`, alg, key)
	}
	return nil
}

// validateEd25519KeyShape reports whether key is a malformed ed25519 key.
// It returns a non-nil error when key is an ed25519 private/public key (value
// or pointer form) that is typed-nil or not the expected length, and nil for
// everything else — including non-ed25519 keys and well-formed ed25519 keys.
//
// Concrete ed25519 keys (and their pointer forms) satisfy crypto.Signer, but
// their Public() method panics ("slice bounds out of range" / nil pointer
// dereference) when the key is not exactly the right size. Callers use this to
// reject malformed keys with an error before any code path reaches Public().
func validateEd25519KeyShape(key any) error {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return fmt.Errorf(`invalid ed25519.PrivateKey length %d, expected %d`, len(k), ed25519.PrivateKeySize)
		}
	case *ed25519.PrivateKey:
		if k == nil || len(*k) != ed25519.PrivateKeySize {
			return fmt.Errorf(`invalid *ed25519.PrivateKey, expected length %d`, ed25519.PrivateKeySize)
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf(`invalid ed25519.PublicKey length %d, expected %d`, len(k), ed25519.PublicKeySize)
		}
	case *ed25519.PublicKey:
		if k == nil || len(*k) != ed25519.PublicKeySize {
			return fmt.Errorf(`invalid *ed25519.PublicKey, expected length %d`, ed25519.PublicKeySize)
		}
	}
	return nil
}

// unsupportedKeyError returns a descriptive error — naming the kid and
// the raw kty, and wrapping Reason() — when key is a
// jwk.UnsupportedKey placeholder retained for an unparseable JWK Set
// entry, and nil otherwise. op names the operation being refused.
// Placeholders carry no usable key material, so they are rejected
// before any Signer or Verifier (default or custom-registered) is
// selected.
func unsupportedKeyError(key any, op string) error {
	uk, ok := key.(jwk.UnsupportedKey)
	if !ok {
		return nil
	}
	kid, _ := uk.KeyID()
	return fmt.Errorf(`key with kid %q has unsupported key type %q and cannot be used for %s; an extension module may be required to parse it: %w`, kid, uk.KeyType().String(), op, uk.Reason())
}

// hasCustomSigVerifier reports whether a non-default Signer or
// Verifier has been registered for alg. When this is true, key-type
// validation must be skipped: the custom implementation decides what
// key types it accepts.
func hasCustomSigVerifier(alg jwa.SignatureAlgorithm) bool {
	if s, ok := signerDB.Load(alg); ok {
		if _, isDefault := s.(defaultSigner); !isDefault {
			return true
		}
	}
	if v, ok := verifierDB.Load(alg); ok {
		if _, isDefault := v.(defaultVerifier); !isDefault {
			return true
		}
	}
	return false
}

// Settings allows you to set global settings for JWS operations.
//
// Returns a non-nil error and applies no changes if any option fails
// validation (for example, a non-positive [WithMaxSignatures]).
func Settings(options ...GlobalOption) error {
	var newMaxSignatures int64
	for _, opt := range options {
		if opt.Ident() == (identMaxSignatures{}) {
			v := option.MustGet[int](opt)
			if v <= 0 {
				return fmt.Errorf(`jws.Settings: WithMaxSignatures must be greater than zero, got %d`, v)
			}
			newMaxSignatures = int64(v)
		}
	}

	if newMaxSignatures > 0 {
		maxSignatures.Store(newMaxSignatures)
	}
	return nil
}

// VerifyCompactFast is a fast path verification function for JWS messages
// in compact serialization format.
//
// This function is considered experimental, and may change or be removed
// in the future.
//
// VerifyCompactFast performs signature verification on a JWS compact
// serialization without fully parsing the message into a jws.Message object.
// This makes it more efficient for cases where you only need to verify
// the signature and extract the payload, without needing access to headers
// or other JWS metadata.
//
// Returns the original payload that was signed if verification succeeds.
//
// Unlike jws.Verify() — which resolves the verification algorithm from the
// key or provider you supply (e.g. WithKey, WithKeySet) — this function takes
// the algorithm as an explicit argument. It is useful for performance-critical
// applications where the algorithm is known in advance.
//
// This function uses strict base64url encoding without padding (RFC 4648 §5)
// for decoding the signature and payload. It does not auto-detect other
// base64 variants. If your JWS uses non-standard encoding (e.g. padded
// base64url), use jws.Verify() instead, which auto-detects the encoding.
//
// Since this function avoids doing many checks that jws.Verify would perform,
// you must ensure to perform the necessary checks including ensuring that algorithm is safe to use for your payload yourself.
//
// VerifyCompactFast cross-checks the protected header's "alg" against
// the caller-supplied alg: if the header omits "alg" (required by
// RFC 7515 §4.1.1) or advertises a different value, it returns a
// verification error. This prevents silently verifying a message
// under a different discipline than the one its header advertises.
//
// VerifyCompactFast refuses messages whose protected header carries a
// "crit" list. RFC 7515 §4.1.11 requires every critical extension to be
// understood by the recipient, and the fast path has no WithCritExtension
// allowlist to consult. On crit-present input it returns a sentinel error
// that callers can detect with errors.Is(err, jws.ErrCritPresent()) and
// retry through jws.Verify, which enforces the full validateCritical rule
// set. Applications that may legitimately receive "crit" headers should
// call jws.Verify directly.
//
// VerifyCompactFast assumes the JWS uses the default "b64":true
// (base64url-encoded) payload encoding. Any protected header carrying
// a "b64" entry is refused with jws.ErrB64Present(), regardless of
// whether "crit" also lists it: the fast path's signing-input
// reconstruction and post-verify base64 decode both depend on the
// default encoding, and a non-conformant b64=false producer (one that
// omits "b64" from "crit") would otherwise verify cryptographically
// while returning bytes that differ from the producer's intent.
// Detached-payload callers must use jws.Verify with jws.WithDetachedPayload
// regardless, since VerifyCompactFast has no way to accept a detached
// payload.
//
// VerifyCompactFast only handles a "minimal" protected header. It proceeds
// with verification only when ALL of the following hold; otherwise it refuses
// with jws.ErrNonMinimalHeader() and the caller should retry through
// jws.Verify:
//
//   - "alg" is present exactly once (a missing "alg" is reported separately,
//     via the cross-check described above, not as ErrNonMinimalHeader);
//   - "typ", "kid", and "cty" each appear at most once;
//   - "typ", "kid", and "cty", when present, have JSON string values (a
//     non-string value, which jws.Verify rejects, is refused here too);
//   - no other parameter is present — this excludes "crit" and "b64" (which
//     have their own dedicated refusals, see above), key-source parameters
//     such as "jwk"/"jku"/"x5u"/"x5c", and any unknown parameter;
//   - the header contains no JSON escape sequences.
//
// The restriction exists because the fast path reads the header with a parser
// that keeps duplicate object members and resolves them first-wins, whereas
// jws.Verify uses encoding/json/v2, which rejects duplicate names outright.
// Limiting the fast path to the minimal shape — and deferring everything else
// to jws.Verify, whose strict, recursive header handling is authoritative —
// makes the two entry points agree on duplicate-name and header-shape handling
// (see issue #2234). It is not a byte-for-byte mirror, though: the fast parser
// does not reproduce all of encoding/json/v2's in-string validation, so a
// header whose "typ"/"kid"/"cty" string value contains e.g. a raw control
// character or invalid UTF-8 is accepted here but rejected by jws.Verify. The
// signature is always verified, so this is a parser-strictness nuance, not a
// bypass; for byte-for-byte parity call jws.Verify. Like the crit refusal,
// ErrNonMinimalHeader means "retry through jws.Verify".
func VerifyCompactFast(key any, compact []byte, alg jwa.SignatureAlgorithm) ([]byte, error) {
	if err := validateAlgorithmForKey(alg, key); err != nil {
		return nil, makeVerifyError(`%w`, err)
	}

	algstr := alg.String()

	// Split the serialized JWS into its components
	hdr, payload, encodedSig, err := jwsbb.SplitCompact(compact)
	if err != nil {
		return nil, makeVerifyError("failed to split compact: %w", err)
	}

	// Decode the protected header ourselves (rather than via
	// HeaderParseCompact) so we can inspect the raw JSON for escape
	// sequences before parsing it.
	decodedHdr, err := base64.Decode(hdr)
	if err != nil {
		return nil, makeVerifyError("failed to decode protected header: %w", err)
	}

	// Refuse any protected header containing a JSON escape sequence. For
	// literal keys fastjson resolves duplicates first-wins deterministically,
	// but for *escaped* keys its resolution becomes order/state-dependent and
	// can diverge from encoding/json/v2 (which jws.Verify uses). Rather than
	// reason about that, defer any escape-bearing header to jws.Verify. The
	// header parameter names the fast path handles (alg/typ/kid/cty) never
	// require escaping; an escape in a value (e.g. a "kid" containing a quote
	// or a control char) is simply deferred to jws.Verify, which handles it.
	if bytes.IndexByte(decodedHdr, '\\') >= 0 {
		return nil, verifyError{fmt.Errorf(`%w (header contains a JSON escape sequence)`, errNonMinimalHeader)}
	}

	// Header probing uses the jwx-internal jwsbb package directly: the
	// enumeration primitive (HeaderForEachKey) the minimal-shape gate below needs
	// is intentionally not part of the public jwsbb facade.
	parsedHdr := jwsbbi.HeaderParse(decodedHdr)

	// Refuse crit-bearing messages: the fast path has no WithCritExtension
	// allowlist, so accepting them would silently violate RFC 7515 §4.1.11.
	// Callers that wrap VerifyCompactFast can detect this via
	// errors.Is(err, jws.ErrCritPresent()) and fall through to jws.Verify.
	// The sentinel is wrapped in verifyError so the same error also matches
	// errors.Is(err, jws.VerifyError()) — fast-path refusals are a verify
	// error, just one with a more specific classification available.
	if jwsbbi.HeaderHas(parsedHdr, CriticalKey) {
		return nil, verifyError{errCritPresent}
	}

	// Refuse "b64"-bearing messages, regardless of whether "crit" also
	// lists it. The signing-input reconstruction and the post-verify
	// base64 decode both assume the default b64=true encoding; a
	// b64=false JWS that the fast path "verified" would either fail the
	// post-verify base64 decode with a misleading error, or — worse —
	// return base64-decoded garbage as the payload while the producer's
	// raw bytes silently disagree. jws.Verify has the WithDetachedPayload
	// / WithCritExtension machinery to handle b64=false correctly. As with
	// the crit refusal above, the sentinel is wrapped in verifyError so the
	// same error matches both jws.ErrB64Present() and jws.VerifyError().
	if jwsbbi.HeaderHas(parsedHdr, B64Key) {
		return nil, verifyError{errB64Present}
	}

	// Minimal-shape gate. fastjson keeps duplicate object members and resolves
	// them first-wins, whereas encoding/json/v2 (jws.Verify) rejects duplicate
	// names — so a header with a duplicate or otherwise unusual parameter
	// could be read differently by the two paths (issue #2234). The fast path
	// therefore only handles the common minimal shape: "alg" exactly once, an
	// optional single "typ"/"kid"/"cty", and nothing else. Anything outside
	// that — a duplicate, a nested object, an unknown or key-source parameter
	// — is deferred to jws.Verify via errNonMinimalHeader, where json/v2's
	// strict recursive duplicate rejection and full header handling apply. A
	// *missing* "alg" is left to the cross-check below so the caller still
	// gets the specific diagnostic.
	//
	// Why gate-here-and-defer rather than teach the header parser to reject
	// duplicates itself:
	//   - The jwsbb header parser is deliberately spec-agnostic: it is a
	//     generic, reusable field-probe (shared with other call sites) that
	//     "does not care about the JWS specification". Baking RFC 7515 §4
	//     header rules into it would break that contract and silently change
	//     behavior for every other consumer.
	//   - A duplicate check inside the parser runs on *every* parse and needs
	//     a per-call set/map allocation, taxing the very hot path the fast
	//     path exists to keep cheap. The shape gate here is a single key sweep
	//     with fixed counters — allocation-free.
	//   - A parser-level top-level dedup would still miss *nested* duplicate
	//     names; deferring unusual headers to jws.Verify inherits json/v2's
	//     strict *recursive* rejection for free, so the two paths agree on
	//     more than just the top level.
	// Gating on shape and handing anything unusual to the authoritative slow
	// path is both cheaper and more complete than making the parser spec-aware.
	var algN, typN, kidN, ctyN, others int
	var firstOther string
	var haveOther bool
	if err := jwsbbi.HeaderForEachKey(parsedHdr, func(name []byte) {
		switch string(name) {
		case AlgorithmKey:
			algN++
		case TypeKey:
			typN++
		case KeyIDKey:
			kidN++
		case ContentTypeKey:
			ctyN++
		default:
			if !haveOther {
				// Capture the first unknown parameter for the diagnostic.
				// Use a bool sentinel (not firstOther == "") so a literal
				// empty-string key is still reported as the first one.
				firstOther = string(name)
				haveOther = true
			}
			others++
		}
	}); err != nil {
		// Header failed to parse or is not a JSON object; let jws.Verify
		// produce the authoritative error.
		return nil, verifyError{fmt.Errorf(`%w (protected header is not a valid JSON object)`, errNonMinimalHeader)}
	}
	// Refuse, naming the specific trigger so the refusal is debuggable. The
	// error still wraps errNonMinimalHeader, so errors.Is classification
	// (ErrNonMinimalHeader / VerifyError) is unchanged.
	if others > 0 || algN > 1 || typN > 1 || kidN > 1 || ctyN > 1 {
		var reason string
		switch {
		case others > 0:
			reason = fmt.Sprintf(`unexpected protected header parameter %q`, firstOther)
		case algN > 1:
			reason = `duplicate "alg"`
		case typN > 1:
			reason = `duplicate "typ"`
		case kidN > 1:
			reason = `duplicate "kid"`
		default: // ctyN > 1
			reason = `duplicate "cty"`
		}
		return nil, verifyError{fmt.Errorf(`%w (%s)`, errNonMinimalHeader, reason)}
	}

	// The optional descriptive parameters must be JSON strings, matching what
	// jws.Verify's typed encoding/json/v2 header decode accepts. Without this,
	// a genuinely-signed header like {"alg":"HS256","typ":123} would pass the
	// name-count gate here yet be rejected by jws.Verify — the same fast/slow
	// divergence the gate exists to prevent. HeaderGetStringBytes reports a
	// non-string value without copying it, so this stays allocation-free; only
	// headers that actually carry typ/kid/cty pay the (negligible) lookup.
	if typN == 1 {
		if _, err := jwsbbi.HeaderGetStringBytes(parsedHdr, TypeKey); err != nil {
			return nil, verifyError{fmt.Errorf(`%w (non-string "typ")`, errNonMinimalHeader)}
		}
	}
	if kidN == 1 {
		if _, err := jwsbbi.HeaderGetStringBytes(parsedHdr, KeyIDKey); err != nil {
			return nil, verifyError{fmt.Errorf(`%w (non-string "kid")`, errNonMinimalHeader)}
		}
	}
	if ctyN == 1 {
		if _, err := jwsbbi.HeaderGetStringBytes(parsedHdr, ContentTypeKey); err != nil {
			return nil, verifyError{fmt.Errorf(`%w (non-string "cty")`, errNonMinimalHeader)}
		}
	}

	// Cross-check the protected header "alg" against the caller-supplied
	// alg. RFC 7515 §4.1.1 makes "alg" mandatory in the protected header
	// for compact serialization, and a mismatch between what the message
	// advertises and the discipline under which we verify is the sort of
	// silent divergence that downstream code (e.g. JWT consumers) should
	// not be asked to re-discover on its own.
	hdrAlg, err := jwsbbi.HeaderGetString(parsedHdr, AlgorithmKey)
	if err != nil {
		return nil, verifyError{verificationError{fmt.Errorf(`jws.Verify: failed to extract %q from protected header: %w`, AlgorithmKey, err)}}
	}
	if hdrAlg != algstr {
		return nil, verifyError{verificationError{fmt.Errorf(`jws.Verify: protected header %q %q does not match caller-supplied algorithm %q`, AlgorithmKey, hdrAlg, algstr)}}
	}

	// Decode signature into pooled buffer (strict base64url, no padding per RFC 7515)
	sigLen := base64.DecodedStrictLen(len(encodedSig))
	sigBuf := pool.ByteSlice().GetCapacity(sigLen)
	sigBuf = sigBuf[:sigLen]
	sigN, err := base64.DecodeStrict(sigBuf, encodedSig)
	if err != nil {
		pool.ByteSlice().Put(sigBuf)
		return nil, makeVerifyError("failed to decode signature: %w", err)
	}
	sigBuf = sigBuf[:sigN]
	defer pool.ByteSlice().Put(sigBuf)

	// Instead of appending, copy the data from hdr/payload
	lvb := len(hdr) + 1 + len(payload)
	verifyBuf := pool.ByteSlice().GetCapacity(lvb)
	verifyBuf = verifyBuf[:lvb]
	copy(verifyBuf, hdr)
	verifyBuf[len(hdr)] = tokens.Period
	copy(verifyBuf[len(hdr)+1:], payload)
	defer pool.ByteSlice().Put(verifyBuf)

	// Verify the signature
	verifier, err := VerifierFor(alg)
	if err != nil {
		return nil, makeVerifyError("failed to create verifier for %s: %w", algstr, err)
	}
	if err := verifier.Verify(key, verifyBuf, sigBuf); err != nil {
		return nil, verifyError{verificationError{fmt.Errorf("signature verification failed for %s: %w", algstr, err)}}
	}

	// Decode payload (strict base64url, no padding per RFC 7515)
	payloadLen := base64.DecodedStrictLen(len(payload))
	decodedPayload := make([]byte, payloadLen)
	payloadN, err := base64.DecodeStrict(decodedPayload, payload)
	if err != nil {
		return nil, makeVerifyError("failed to decode payload: %w", err)
	}
	return decodedPayload[:payloadN], nil
}
