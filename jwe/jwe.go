//go:generate ../scripts/jwxcodegen.sh generate-headers -objects=objects.yml

// Package jwe implements JWE as described in https://tools.ietf.org/html/rfc7516.
//
// Legacy note: RSA-PKCS1 v1.5 key encryption (`jwa.RSA1_5()`) is supported
// only for interoperability with existing peers. New applications should
// prefer an RSA-OAEP variant such as `jwa.RSA_OAEP_256()` because PKCS#1 v1.5
// decryption is exposed to Bleichenbacher-style oracle attacks.
package jwe

// #region imports
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync/atomic"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/aescbc"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/content_crypt"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/lestrrat-go/option/v3"
)

// #region globals

var maxPBES2Count atomic.Int64
var minPBES2Count atomic.Int64
var pbes2Count atomic.Int64
var maxRecipients atomic.Int64
var maxDecompressBufferSize atomic.Int64
var disabledKeyAlgs atomic.Pointer[map[string]struct{}]

func init() {
	// maxPBES2Count: 1_000_000 covers OWASP 2023's 600k HS256 floor with
	// headroom for peers that ship higher. PBES2 decrypt is only reachable
	// when the caller explicitly configures a password key, so this cap
	// gates per-attempt cost, not exposure.
	maxPBES2Count.Store(1_000_000)
	minPBES2Count.Store(1000)
	// pbes2Count: 0 means "no global override" — the per-variant default
	// in jwebb.KeyEncryptPBES2 applies.
	pbes2Count.Store(0)
	maxRecipients.Store(100)
	maxDecompressBufferSize.Store(10 * 1024 * 1024) // 10MB
}

// Settings configures process-global behavior for JWE operations.
func Settings(options ...GlobalOption) error {
	for _, opt := range options {
		switch opt.Ident() {
		case identMaxPBES2Count{}:
			maxPBES2Count.Store(int64(option.MustGet[int](opt)))
		case identMinPBES2Count{}:
			minPBES2Count.Store(int64(option.MustGet[int](opt)))
		case identPBES2Count{}:
			// 0 means "reset to per-variant defaults"; clamp negatives.
			v := max(option.MustGet[int](opt), 0)
			pbes2Count.Store(int64(v))
		case identMaxRecipients{}:
			maxRecipients.Store(int64(option.MustGet[int](opt)))
		case identMaxDecompressBufferSize{}:
			maxDecompressBufferSize.Store(option.MustGet[int64](opt))
		case identCBCBufferSize{}:
			aescbc.SetMaxBufferSize(option.MustGet[int64](opt))
		case identDisabledKeyAlgorithms{}:
			algs := option.MustGet[[]jwa.KeyEncryptionAlgorithm](opt)
			if len(algs) == 0 {
				disabledKeyAlgs.Store(nil)
				continue
			}
			m := make(map[string]struct{}, len(algs))
			for _, alg := range algs {
				m[alg.String()] = struct{}{}
			}
			disabledKeyAlgs.Store(&m)
		}
	}
	return nil
}

// isKeyAlgorithmDisabled reports whether alg is in the global
// jwe.WithDisabledKeyAlgorithms set.
func isKeyAlgorithmDisabled(alg jwa.KeyEncryptionAlgorithm) bool {
	m := disabledKeyAlgs.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[alg.String()]
	return ok
}

const (
	fmtInvalid = iota
	fmtCompact
	fmtJSON
	fmtJSONPretty
	fmtMax
)

var registry = json.NewRegistry()

type recipientBuilder struct {
	alg        jwa.KeyEncryptionAlgorithm
	key        any
	headers    Headers
	pbes2Count int
}

func (b *recipientBuilder) Build(r Recipient, cek []byte, calg jwa.ContentEncryptionAlgorithm) ([]byte, error) {
	if isKeyAlgorithmDisabled(b.alg) {
		return nil, fmt.Errorf(`jwe.Encrypt: key encryption algorithm %q is disabled by jwe.WithDisabledKeyAlgorithms`, b.alg)
	}
	// Resolve the key to its raw form and extract key ID.
	resolvedKey := b.key

	var keyID string
	if ke, ok := b.key.(KeyEncrypter); ok {
		// Custom key encrypter (e.g. HSM) — handle directly without
		// going through the normal encrypter dispatch.
		if kider, ok := ke.(KeyIDer); ok {
			if v, ok := kider.KeyID(); ok {
				keyID = v
			}
		}

		hdr := b.headers
		if hdr == nil {
			hdr = r.Headers()
		}

		_ = r.SetHeaders(hdr)

		if err := hdr.Set(AlgorithmKey, b.alg); err != nil {
			return nil, fmt.Errorf(`failed to set header: %w`, err)
		}
		if keyID != "" {
			if err := hdr.Set(KeyIDKey, keyID); err != nil {
				return nil, fmt.Errorf(`failed to set header: %w`, err)
			}
		}

		encrypted, err := ke.EncryptKey(cek)
		if err != nil {
			return nil, fmt.Errorf(`failed to encrypt key: %w`, err)
		}
		if err := r.SetEncryptedKey(encrypted); err != nil {
			return nil, fmt.Errorf(`failed to set encrypted key: %w`, err)
		}
		return nil, nil
	}

	if jwkKey, ok := b.key.(jwk.Key); ok {
		if v, ok := jwkKey.KeyID(); ok {
			keyID = v
		}

		raw, err := jwk.Export[any](jwkKey)
		if err != nil {
			return nil, fmt.Errorf(`jwe.Encrypt: recipientBuilder: failed to retrieve raw key out of %T: %w`, b.key, err)
		}

		resolvedKey = raw
	}

	// Extract ECDH-ES specific parameters if needed.
	var apu, apv []byte

	hdr := b.headers
	if hdr == nil {
		hdr = r.Headers()
	} else {
		_ = r.SetHeaders(hdr)
	}

	if val, ok := hdr.AgreementPartyUInfo(); ok {
		apu = val
	}

	if val, ok := hdr.AgreementPartyVInfo(); ok {
		apv = val
	}

	// Populate headers with stuff that we automatically set.
	// Use setNoLock when possible since the header is either freshly
	// created or owned exclusively by this builder.
	if sh, ok := hdr.(*stdHeaders); ok {
		if err := sh.setNoLock(AlgorithmKey, b.alg); err != nil {
			return nil, fmt.Errorf(`failed to set header: %w`, err)
		}
		if keyID != "" {
			if err := sh.setNoLock(KeyIDKey, keyID); err != nil {
				return nil, fmt.Errorf(`failed to set header: %w`, err)
			}
		}
	} else {
		if err := hdr.Set(AlgorithmKey, b.alg); err != nil {
			return nil, fmt.Errorf(`failed to set header: %w`, err)
		}
		if keyID != "" {
			if err := hdr.Set(KeyIDKey, keyID); err != nil {
				return nil, fmt.Errorf(`failed to set header: %w`, err)
			}
		}
	}

	// Handle the encrypted key
	var rawCEK []byte
	enckey, err := encryptKey(cek, b.alg, calg, resolvedKey, apu, apv, b.pbes2Count)
	if err != nil {
		return nil, fmt.Errorf(`failed to encrypt key: %w`, err)
	}
	if jwebb.IsDirectCEK(b.alg.String()) {
		rawCEK = enckey.Bytes()
	} else {
		if err := r.SetEncryptedKey(enckey.Bytes()); err != nil {
			return nil, fmt.Errorf(`failed to set encrypted key: %w`, err)
		}
	}

	// finally, anything specific should go here
	if hp, ok := enckey.(populater); ok {
		if err := hp.Populate(hdr); err != nil {
			return nil, fmt.Errorf(`failed to populate: %w`, err)
		}
	}

	return rawCEK, nil
}

// Encrypt generates a JWE message for the given payload and returns
// it in serialized form, which can be in either compact or
// JSON format. Default is compact. When JSON format is specified and
// there is only one recipient, the resulting serialization is
// automatically converted to flattened JSON serialization format.
//
// You must pass at least one key to `jwe.Encrypt()` by using `jwe.WithKey()`
// option.
//
//	jwe.Encrypt(payload, jwe.WithKey(alg, key))
//	jwe.Encrypt(payload, jwe.WithJSON(), jwe.WithKey(alg1, key1), jwe.WithKey(alg2, key2))
//
// Note that in the second example the `jwe.WithJSON()` option is
// specified as well. This is because the compact serialization
// format does not support multiple recipients, and users must
// specifically ask for the JSON serialization format.
//
// Read the documentation for `jwe.WithKey()` to learn more about the
// possible values that can be used for `alg` and `key`.
//
// `jwa.RSA1_5()` is supported only for interoperability with legacy peers.
// New applications should prefer an RSA-OAEP variant such as
// `jwa.RSA_OAEP_256()` because PKCS#1 v1.5 decryption is exposed to
// Bleichenbacher-style oracle attacks.
// If you enable `jwe.WithCompress()`, this library does not enforce a
// producer-side payload size limit before compression. Callers that accept
// untrusted or arbitrarily large plaintext must bound the input size before
// calling `jwe.Encrypt()`. Recipients may also reject compressed messages
// whose decompressed payload exceeds their `jwe.WithMaxDecompressBufferSize()`
// setting.
//
// Look for options that return `jwe.EncryptOption` or `jwe.EncryptDecryptOption`
// for a complete list of options that can be passed to this function.
func Encrypt(payload []byte, options ...EncryptOption) ([]byte, error) {
	ec := encryptContextPool.Get()
	defer encryptContextPool.Put(ec)
	if err := ec.ProcessOptions(options); err != nil {
		return nil, makeEncryptError(`jwe.Encrypt`, `failed to process options: %w`, err)
	}
	ret, err := ec.EncryptMessage(payload, nil)
	if err != nil {
		return nil, makeEncryptError(`jwe.Encrypt`, `%w`, err)
	}
	return ret, nil
}

// EncryptStatic is exactly like Encrypt, except it accepts a static
// content encryption key (CEK). It is separated out from the main
// Encrypt function such that the latter does not accidentally use a static
// CEK.
//
// Unless `jwe.WithContentEncryption()` is provided, `EncryptStatic` uses
// `jwa.A256GCM()`, which requires a 32-byte CEK.
//
// The CEK used to encrypt the payload must match the selected content
// encryption algorithm:
//
//   - `jwa.A128GCM()`: 16 bytes
//   - `jwa.A192GCM()`: 24 bytes
//   - `jwa.A256GCM()`: 32 bytes
//   - `jwa.A128CBC_HS256()`: 32 bytes
//   - `jwa.A192CBC_HS384()`: 48 bytes
//   - `jwa.A256CBC_HS512()`: 64 bytes
//
// `EncryptStatic` validates the final CEK length before payload encryption
// and returns an error if it does not match the selected `enc` algorithm.
//
// NOTE: when the chosen key-encryption algorithm derives the CEK rather than
// wrapping it — specifically `jwa.DIRECT()`, bare `jwa.ECDH_ES()` (without
// a key-wrap suffix), and direct ML-KEM modes — the `cek` argument supplied
// here is ignored for content encryption. In those modes the effective CEK
// is the shared/derived key produced by the `jwe.WithKey()` input, and the
// byte-length check described above is enforced against that derived CEK,
// not against the value passed as `cek`. To pin the CEK deterministically,
// pair `EncryptStatic` only with key-wrapping algorithms such as
// `jwa.RSA_OAEP()`, `jwa.A256KW()`, or `jwa.ECDH_ES_A256KW()`.
//
// DO NOT attempt to use this function unless you completely understand the
// security implications to using static CEKs. You have been warned.
//
// This function is currently considered EXPERIMENTAL, and is subject to
// future changes across minor/micro versions.
func EncryptStatic(payload, cek []byte, options ...EncryptOption) ([]byte, error) {
	if len(cek) <= 0 {
		return nil, makeEncryptError(`jwe.EncryptStatic`, `empty CEK`)
	}
	ec := encryptContextPool.Get()
	defer encryptContextPool.Put(ec)
	if err := ec.ProcessOptions(options); err != nil {
		return nil, makeEncryptError(`jwe.EncryptStatic`, `failed to process options: %w`, err)
	}
	ret, err := ec.EncryptMessage(payload, cek)
	if err != nil {
		return nil, makeEncryptError(`jwe.EncryptStatic`, `%w`, err)
	}
	return ret, nil
}

// decryptContext holds the state during JWE decryption, similar to JWS verifyContext
type decryptContext struct {
	keyProviders            []KeyProvider
	keyUsed                 *any
	cek                     *[]byte
	dst                     *Message
	maxRecipients           int
	maxDecompressBufferSize int64
	maxPBES2Count           int
	minPBES2Count           int
	critValidation          bool
	criticalExtensions      []string
	//nolint:containedctx
	ctx context.Context
}

var decryptContextPool = pool.New(allocDecryptContext, freeDecryptContext)

func allocDecryptContext() *decryptContext {
	return &decryptContext{
		critValidation: true,
		ctx:            context.Background(),
	}
}

func freeDecryptContext(dc *decryptContext) *decryptContext {
	dc.keyProviders = dc.keyProviders[:0]
	dc.keyUsed = nil
	dc.cek = nil
	dc.dst = nil
	dc.maxRecipients = 0
	dc.maxDecompressBufferSize = 0
	dc.maxPBES2Count = 0
	dc.minPBES2Count = 0
	dc.critValidation = true
	dc.criticalExtensions = dc.criticalExtensions[:0]
	dc.ctx = context.Background()
	return dc
}

func (dc *decryptContext) ProcessOptions(options []DecryptOption) error {
	dc.maxRecipients = int(maxRecipients.Load())
	dc.maxDecompressBufferSize = maxDecompressBufferSize.Load()
	dc.maxPBES2Count = int(maxPBES2Count.Load())
	dc.minPBES2Count = int(minPBES2Count.Load())

	var ctxOpt context.Context
	for _, opt := range options {
		switch opt.Ident() {
		case identMessage{}:
			dc.dst = option.MustGet[*Message](opt)
		case identKeyProvider{}:
			dc.keyProviders = append(dc.keyProviders, option.MustGet[KeyProvider](opt))
		case identKeyUsed{}:
			dc.keyUsed = option.MustGet[*any](opt)
		case identKey{}:
			pair := option.MustGet[*withKey](opt)
			alg, ok := pair.alg.(jwa.KeyEncryptionAlgorithm)
			if !ok {
				return fmt.Errorf("jwe.decrypt: WithKey() option must be specified using jwa.KeyEncryptionAlgorithm (got %T)", pair.alg)
			}
			if err := validateAlgorithmForKey(alg, pair.key); err != nil {
				return fmt.Errorf("jwe.WithKey: %w", err)
			}
			dc.keyProviders = append(dc.keyProviders, &staticKeyProvider{alg: alg, key: pair.key})
		case identCEK{}:
			dc.cek = option.MustGet[*[]byte](opt)
		case identMaxRecipients{}:
			dc.maxRecipients = option.MustGet[int](opt)
		case identMaxDecompressBufferSize{}:
			dc.maxDecompressBufferSize = option.MustGet[int64](opt)
		case identMaxPBES2Count{}:
			dc.maxPBES2Count = option.MustGet[int](opt)
		case identMinPBES2Count{}:
			dc.minPBES2Count = option.MustGet[int](opt)
		case identContext{}:
			ctxOpt = option.MustGet[context.Context](opt) //nolint:fatcontext // not nesting; selecting from options
		case identCritValidation{}:
			dc.critValidation = option.MustGet[bool](opt)
		case identCritExtension{}:
			dc.criticalExtensions = append(dc.criticalExtensions, option.MustGet[[]string](opt)...)
		}
	}
	if ctxOpt != nil {
		dc.ctx = ctxOpt
	}

	if len(dc.keyProviders) < 1 {
		return fmt.Errorf(`jwe.Decrypt: no decrypters available. Specify an algorithm and a key using jwe.WithKey() (or jwe.WithKeySet() or jwe.WithKeyProvider())`)
	}

	return nil
}

// validateCritical checks the "crit" header per RFC 7516 Section 4.1.13
// (which references RFC 7515 Section 4.1.11). It enforces:
//   - the list is non-empty
//   - no entry is the empty string
//   - no entry duplicates another
//   - no entry names a standard JOSE/JWE header parameter
//   - every entry appears as a header parameter in the protected header
//   - every entry is in the caller-supplied allowedExtensions allowlist
//
// The last check is the central RFC requirement: recipients MUST reject
// any "crit" extension they do not understand, and the only way the
// library knows which extensions the caller understands is via the
// allowlist (populated from jwe.WithCritExtension()).
func validateCritical(protected Headers, allowedExtensions []string) error {
	if !protected.Has(CriticalKey) {
		return nil
	}

	crit, _ := protected.Critical()
	if len(crit) == 0 {
		return makeDecryptError(`"crit" header must not be empty`)
	}

	seen := make(map[string]struct{}, len(crit))
	for _, name := range crit {
		if name == "" {
			return makeDecryptError(`"crit" header must not contain an empty extension name`)
		}
		if _, dup := seen[name]; dup {
			return makeDecryptError(`"crit" header must not contain duplicate extension %q`, name)
		}
		seen[name] = struct{}{}

		// RFC 7515 Section 4.1.11: "crit" MUST NOT include names defined
		// by the JOSE Header specification itself.
		if slices.Contains(stdHeaderNames, name) {
			return makeDecryptError(`"crit" header must not contain standard header parameter %q`, name)
		}

		// The extension must be present in the protected header.
		if !protected.Has(name) {
			return makeDecryptError(`"crit" header references extension %q, but it is not present in the protected header`, name)
		}

		// The recipient must have declared support for the extension.
		if !slices.Contains(allowedExtensions, name) {
			return makeDecryptError(`"crit" header references extension %q, but the recipient has not declared support for it (use jwe.WithCritExtension(%q))`, name, name)
		}
	}

	return nil
}

// concatAAD returns the AAD value used to seal or open a JWE payload:
// the protected-header segment, optionally followed by ASCII '.' and
// the caller-supplied external aad (RFC 7516 §5.1 step 14 / §5.2
// step 14). A fresh slice is always allocated so the caller's computed
// and aad slices are never appended into, which matters because
// computedAad often aliases a Message field whose backing array is
// still referenced elsewhere.
func concatAAD(computed, aad []byte) []byte {
	if len(aad) == 0 {
		return computed
	}
	out := make([]byte, len(computed)+1+len(aad))
	n := copy(out, computed)
	out[n] = tokens.Period
	copy(out[n+1:], aad)
	return out
}

func (dc *decryptContext) DecryptMessage(buf []byte) ([]byte, error) {
	msg, err := parseJSONOrCompact(buf, true, dc.maxRecipients)
	if err != nil {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to parse buffer: %w`, err)
	}

	// Validate the "crit" header per RFC 7516 Section 4.1.13. The check
	// runs against the protected header only — RFC says "crit" MUST live
	// there — and short-circuits before any key-decrypt or content-decrypt
	// work happens.
	if dc.critValidation {
		if err := validateCritical(msg.protectedHeaders, dc.criticalExtensions); err != nil {
			return nil, err
		}
	}

	// Clone the shared (top-level) protected header as our working copy.
	// We deliberately do NOT merge msg.unprotectedHeaders (the shared,
	// top-level *unprotected* header) here: it is never covered by the
	// AEAD tag, so it must not contribute algorithm parameters.
	//
	// Per-recipient unprotected headers are a separate case — RFC 7516
	// §5.3 explicitly permits them to carry recipient-specific algorithm
	// parameters (alg, epk, p2s, p2c, iv, tag, apu, apv, …), and
	// decryptContent merges recipient.Headers() onto this base below.
	// That merge is bounded by WithMaxRecipients and, for PBES2, by
	// WithMaxPBES2Count (applied per recipient).
	h, err := msg.protectedHeaders.Clone()
	if err != nil {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to copy protected headers: %w`, err)
	}

	var aad []byte
	if aadContainer := msg.authenticatedData; aadContainer != nil {
		aad = base64.Encode(aadContainer)
	}

	var computedAad []byte
	if len(msg.rawProtectedHeaders) > 0 {
		computedAad = msg.rawProtectedHeaders
	} else {
		// this is probably not required once msg.Decrypt is deprecated
		var err error
		computedAad, err = msg.protectedHeaders.Encode()
		if err != nil {
			return nil, fmt.Errorf(`jwe.Decrypt: failed to encode protected headers: %w`, err)
		}
	}

	// for each recipient, attempt to match the key providers
	// if we have no recipients, pretend like we only have one
	recipients := msg.recipients
	if len(recipients) == 0 {
		r := NewRecipient()
		if err := r.SetHeaders(msg.protectedHeaders); err != nil {
			return nil, fmt.Errorf(`jwe.Decrypt: failed to set headers to recipient: %w`, err)
		}
		recipients = append(recipients, r)
	}

	errs := make([]error, 0, len(recipients))
	for _, recipient := range recipients {
		// Honor caller's deadline between recipients. Without this
		// check, a hostile JWE with many recipients keeps the loop
		// running long after the deadline. Symmetric with the
		// per-keyProvider and per-(alg,key) checks in tryRecipient.
		if err := dc.ctx.Err(); err != nil {
			return nil, makeDecryptError(`%w`, err)
		}

		decrypted, err := dc.tryRecipient(msg, recipient, h, aad, computedAad)
		if err != nil {
			errs = append(errs, makeRecipientError(err))
			continue
		}
		if dc.dst != nil {
			*dc.dst = *msg
			dc.dst.rawProtectedHeaders = nil
			dc.dst.storeProtectedHeaders = false
		}
		return decrypted, nil
	}
	// Bound the joined-error count so a hostile JWE with many recipients
	// can't produce an unbounded error string. R×K errors at default
	// MaxRecipients=100 with a multi-key keyset can otherwise grow into
	// a log-spam vector. Keep the first decryptErrorJoinCap entries
	// verbatim and replace the rest with a single "... and N more" sentinel.
	return nil, fmt.Errorf(`jwe.Decrypt: failed to decrypt any of the recipients: %w`, joinDecryptErrors(errs))
}

// decryptErrorJoinCap caps how many per-recipient / per-(alg,key)
// constituent errors get joined into the final Decrypt error. A
// hostile JWE with R recipients × K keys produces R×K constituent
// errors; the cap prevents the resulting err.Error() string from
// growing unboundedly.
const decryptErrorJoinCap = 10

func joinDecryptErrors(errs []error) error {
	if len(errs) <= decryptErrorJoinCap {
		return errors.Join(errs...)
	}
	kept := make([]error, decryptErrorJoinCap, decryptErrorJoinCap+1)
	copy(kept, errs[:decryptErrorJoinCap])
	kept = append(kept, fmt.Errorf("... and %d more error(s) suppressed", len(errs)-decryptErrorJoinCap))
	return errors.Join(kept...)
}

func (dc *decryptContext) tryRecipient(msg *Message, recipient Recipient, protectedHeaders Headers, aad, computedAad []byte) ([]byte, error) {
	var tried int
	var attemptErrors []error
	for i, kp := range dc.keyProviders {
		// Honor caller's deadline between key providers.
		if err := dc.ctx.Err(); err != nil {
			return nil, err
		}

		var sink algKeySink
		if err := kp.FetchKeys(dc.ctx, &sink, recipient, msg); err != nil {
			return nil, fmt.Errorf(`key provider %d failed: %w`, i, err)
		}

		for _, pair := range sink.list {
			// Honor caller's deadline between (alg,key) pairs.
			// Under WithRequireKid(false) + a large keyset, this
			// inner loop is the dominant cost — checking ctx
			// between attempts caps the post-deadline crypto
			// work at one operation.
			if err := dc.ctx.Err(); err != nil {
				return nil, err
			}

			tried++
			// alg is converted here because pair.alg is of type jwa.KeyAlgorithm.
			// this may seem ugly, but we're trying to avoid declaring separate
			// structs for `alg jwa.KeyEncryptionAlgorithm` and `alg jwa.SignatureAlgorithm`
			//nolint:forcetypeassert
			alg := pair.alg.(jwa.KeyEncryptionAlgorithm)
			key := pair.key

			decrypted, err := dc.decryptContent(msg, alg, key, recipient, protectedHeaders, aad, computedAad)
			if err != nil {
				attemptErrors = append(attemptErrors, err)
				continue
			}

			if dc.keyUsed != nil {
				*dc.keyUsed = key
			}
			return decrypted, nil
		}
	}
	// Preserve per-key attempt errors via errors.Join so each constituent
	// remains reachable through errors.Is / errors.As on the outer error.
	// Cap the count so a hostile JWE with many keys per provider can't
	// produce unbounded error text. Top-level "jwe.Decrypt:" prefix is
	// added by the caller (Decrypt) via makeDecryptError.
	return nil, fmt.Errorf(`tried %d keys, but failed to match any of the keys with recipient: %w`, tried, joinDecryptErrors(attemptErrors))
}

func (dc *decryptContext) decryptContent(msg *Message, alg jwa.KeyEncryptionAlgorithm, key any, recipient Recipient, protectedHeaders Headers, aad, computedAad []byte) ([]byte, error) {
	if isKeyAlgorithmDisabled(alg) {
		return nil, decryptError{fmt.Errorf(`jwe.Decrypt: key encryption algorithm %q is disabled by jwe.WithDisabledKeyAlgorithms`, alg)}
	}
	if jwkKey, ok := key.(jwk.Key); ok {
		raw, err := jwk.Export[any](jwkKey)
		if err != nil {
			return nil, fmt.Errorf(`failed to retrieve raw key from %T: %w`, key, err)
		}
		key = raw
	}

	ce, ok := msg.protectedHeaders.ContentEncryption()
	if !ok {
		return nil, decryptError{fmt.Errorf(`jwe.Decrypt: %w`, MissingContentEncryptionError{})}
	}

	// RFC 7516 §7.2.1 requires header parameter names to be disjoint
	// across the protected, shared-unprotected, and per-recipient
	// header locations. For "alg" specifically, allowing protected
	// and per-recipient headers to declare conflicting values is an
	// algorithm-confusion vector: an attacker who can rewrite the
	// per-recipient (unprotected) location can claim a different alg
	// than the integrity-protected one, and the alg-match loop below
	// would silently break on whichever it sees first.
	//
	// Compact-form JWE legitimately has the same alg value in both
	// places — parseCompact synthesizes a per-recipient header by
	// cloning the protected header (minus enc), so a strict-disjoint
	// check would reject every compact JWE. We therefore allow the
	// duplication when the values agree, and reject only when they
	// disagree. The shared unprotected header is ignored elsewhere
	// in this function (see comment at the top) and so does not
	// participate here either.
	if rh := recipient.Headers(); rh != nil {
		if recipAlg, recipHas := rh.Algorithm(); recipHas {
			if protectedAlg, protectedHas := protectedHeaders.Algorithm(); protectedHas && protectedAlg != recipAlg {
				return nil, decryptError{fmt.Errorf(`jwe.Decrypt: malformed JWE — "alg" header value differs between protected (%q) and per-recipient (%q) headers (RFC 7516 §7.2.1)`, protectedAlg, recipAlg)}
			}
		}
	}

	// The "alg" header can be in either protected or per-recipient
	// headers. With disjointness enforced above, only one location can
	// have it, so iteration order does not affect security; we keep
	// per-recipient first to match the historical preference for
	// recipient-specific algs in multi-recipient JWE.
	var algMatched bool
	for _, hdr := range []Headers{recipient.Headers(), protectedHeaders} {
		v, ok := hdr.Algorithm()
		if !ok {
			continue
		}

		if v == alg {
			algMatched = true
			break
		}
		// if we found something but didn't match, it's a failure
		return nil, decryptError{fmt.Errorf(`jwe.Decrypt: %w`, AlgorithmMismatchError{Expected: alg, Got: v})}
	}
	if !algMatched {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to find "alg" header in either protected or per-recipient headers`)
	}

	// Merge protected and per-recipient headers for algorithm-specific param extraction.
	// When recipient headers are empty (common in compact format), skip the
	// expensive Clone+Merge and use protected headers directly.
	var h2 Headers
	recipientHdrs := recipient.Headers()
	if iz, ok := recipientHdrs.(isZeroer); ok && iz.isZero() {
		h2 = protectedHeaders
	} else {
		var err error
		h2, err = protectedHeaders.Clone()
		if err != nil {
			return nil, fmt.Errorf(`jwe.Decrypt: failed to copy headers (1): %w`, err)
		}
		h2, err = h2.Merge(recipientHdrs)
		if err != nil {
			return nil, fmt.Errorf(`jwe.Decrypt: failed to merge headers: %w`, err)
		}
	}

	// Create content cipher (needed by RSA-1.5 for key size, and for content decryption)
	contentCipher, err := jwebb.CreateContentCipher(ce.String())
	if err != nil {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to create content cipher: %w`, err)
	}

	// Decrypt the CEK using per-family dispatch.
	// Each function extracts its own algorithm-specific params from merged headers.
	cekCtx := &decryptCEKContext{
		maxPBES2Count: dc.maxPBES2Count,
		minPBES2Count: dc.minPBES2Count,
		ctalg:         ce,
		contentCipher: contentCipher,
	}
	cek, err := decryptCEK(alg, key, msg, recipient, h2, cekCtx)
	if err != nil {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to decrypt key: %w`, err)
	}

	// Decrypt the payload. When an external aad is present we must NOT
	// append into computedAad's backing array: computedAad aliases
	// msg.rawProtectedHeaders, and appending would mutate bytes past
	// its length in storage still referenced by the Message.
	computedAadFull := concatAAD(computedAad, aad)

	plaintext, err := contentCipher.Decrypt(cek, msg.initializationVector, msg.cipherText, msg.tag, computedAadFull)
	if err != nil {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to decrypt payload: %w`, err)
	}

	if v, ok := h2.Compression(); ok && v == jwa.Deflate() {
		buf, err := uncompress(plaintext, dc.maxDecompressBufferSize)
		if err != nil {
			return nil, fmt.Errorf(`jwe.Decrypt: failed to uncompress payload: %w`, err)
		}
		plaintext = buf
	}

	// Expose the CEK only after the content cipher has authenticated it.
	// Writing earlier would hand the caller an unverified CEK on AEAD
	// failure (JWE-021).
	if dc.cek != nil {
		*dc.cek = cek
	}

	return plaintext, nil
}

// encryptContext holds the state during JWE encryption, similar to JWS signContext
type encryptContext struct {
	calg        jwa.ContentEncryptionAlgorithm
	compression jwa.CompressionAlgorithm
	format      int
	pbes2Count  int
	builders    []*recipientBuilder
	protected   Headers
	builderBuf  [1]recipientBuilder // inline storage for common single-recipient case
}

var encryptContextPool = pool.New(allocEncryptContext, freeEncryptContext)

func allocEncryptContext() *encryptContext {
	return &encryptContext{
		calg:        jwa.A256GCM(),
		compression: jwa.NoCompress(),
		format:      fmtCompact,
	}
}

func freeEncryptContext(ec *encryptContext) *encryptContext {
	ec.calg = jwa.A256GCM()
	ec.compression = jwa.NoCompress()
	ec.format = fmtCompact
	ec.pbes2Count = 0
	ec.builders = ec.builders[:0]
	ec.protected = nil
	ec.builderBuf[0] = recipientBuilder{}
	return ec
}

func (ec *encryptContext) ProcessOptions(options []EncryptOption) error {
	ec.pbes2Count = int(pbes2Count.Load())
	var mergeProtected bool
	var useRawCEK bool
	for _, opt := range options {
		switch opt.Ident() {
		case identPBES2Count{}:
			v := option.MustGet[int](opt)
			if v > 0 {
				ec.pbes2Count = v
			}
		case identKey{}:
			wk := option.MustGet[*withKey](opt)
			v, ok := wk.alg.(jwa.KeyEncryptionAlgorithm)
			if !ok {
				return fmt.Errorf("jwe.encrypt: WithKey() option must be specified using jwa.KeyEncryptionAlgorithm (got %T)", wk.alg)
			}
			if err := validateAlgorithmForKey(v, wk.key); err != nil {
				return fmt.Errorf("jwe.WithKey: %w", err)
			}
			if jwebb.IsDirectCEK(v.String()) {
				useRawCEK = true
			}
			var rb *recipientBuilder
			if len(ec.builders) == 0 {
				rb = &ec.builderBuf[0]
			} else {
				rb = &recipientBuilder{}
			}
			rb.alg = v
			rb.key = wk.key
			rb.headers = wk.headers
			ec.builders = append(ec.builders, rb)
		case identContentEncryptionAlgorithm{}:
			ec.calg = option.MustGet[jwa.ContentEncryptionAlgorithm](opt)
		case identCompress{}:
			ec.compression = option.MustGet[jwa.CompressionAlgorithm](opt)
		case identMergeProtectedHeaders{}:
			mergeProtected = option.MustGet[bool](opt)
		case identProtectedHeaders{}:
			hdrs := option.MustGet[Headers](opt)
			if !mergeProtected || ec.protected == nil {
				ec.protected = hdrs
			} else {
				merged, err := ec.protected.Merge(hdrs)
				if err != nil {
					return fmt.Errorf(`failed to merge headers: %w`, err)
				}
				ec.protected = merged
			}
		case identSerialization{}:
			ec.format = option.MustGet[int](opt)
		}
	}

	// We need to have at least one builder
	switch l := len(ec.builders); {
	case l == 0:
		return fmt.Errorf(`no encrypters available. Specify an algorithm and a key using jwe.WithKey()`)
	case l > 1:
		if ec.format == fmtCompact {
			return fmt.Errorf(`cannot use compact serialization when multiple recipients exist (check the number of WithKey() argument, or use WithJSON())`)
		}
	}

	if useRawCEK {
		if len(ec.builders) != 1 {
			return fmt.Errorf(`multiple recipients for ECDH-ES/DIRECT mode are not supported`)
		}
	}

	return nil
}

var msgPool = pool.New(allocMessage, freeMessage)

func allocMessage() *Message {
	return &Message{
		recipients: make([]Recipient, 0, 1),
	}
}

func freeMessage(msg *Message) *Message {
	msg.cipherText = nil
	msg.initializationVector = nil
	if hdr := msg.protectedHeaders; hdr != nil {
		headerPool.Put(hdr)
	}
	msg.protectedHeaders = nil
	msg.unprotectedHeaders = nil
	msg.recipients = nil // reuse should be done elsewhere
	msg.authenticatedData = nil
	msg.tag = nil
	msg.rawProtectedHeaders = nil
	msg.storeProtectedHeaders = false
	return msg
}

var headerPool = pool.New(NewHeaders, freeHeaders)

func freeHeaders(h Headers) Headers {
	if c, ok := h.(interface{ clear() }); ok {
		c.clear()
	}
	return h
}

var recipientPool = pool.New(NewRecipient, freeRecipient)

func freeRecipient(r Recipient) Recipient {
	// Return the recipient's headers to headerPool and install a fresh
	// instance so the next recipientPool.Get() never hands out a
	// pointer the caller may still hold a reference to. This is safe
	// because WithPerRecipientHeaders clones the caller-supplied
	// Headers, so anything we receive here is already library-owned.
	if h := r.Headers(); h != nil {
		headerPool.Put(h)
		_ = r.SetHeaders(headerPool.Get())
	}

	if sr, ok := r.(*stdRecipient); ok {
		sr.encryptedKey = nil
	}
	return r
}

var recipientSlicePool = pool.NewSlicePool(allocRecipientSlice, freeRecipientSlice)

func allocRecipientSlice() []Recipient {
	return make([]Recipient, 0, 1)
}

func freeRecipientSlice(rs []Recipient) []Recipient {
	for _, r := range rs {
		recipientPool.Put(r)
	}
	return rs[:0]
}

func (ec *encryptContext) EncryptMessage(payload []byte, cek []byte) ([]byte, error) {
	// Get protected headers from pool and copy contents from context.
	// We use the concrete *stdHeaders type to enable lock-free field
	// access since pool-obtained headers are not shared.
	protected, _ := headerPool.Get().(*stdHeaders)
	if userSupplied := ec.protected; userSupplied != nil {
		ec.protected = nil // Clear from context
		if src, ok := userSupplied.(*stdHeaders); ok {
			src.copyNoLock(protected)
		} else {
			if err := userSupplied.Copy(protected); err != nil {
				return nil, fmt.Errorf(`failed to copy protected headers: %w`, err)
			}
		}
	}

	// There is exactly one content encrypter.
	contentcrypt, err := content_crypt.NewGeneric(ec.calg)
	if err != nil {
		return nil, fmt.Errorf(`failed to create AES encrypter: %w`, err)
	}

	// Generate CEK if not provided
	if len(cek) <= 0 {
		bk, err := keygen.Random(contentcrypt.KeySize())
		if err != nil {
			return nil, fmt.Errorf(`failed to generate key: %w`, err)
		}
		cek = bk.Bytes()
	}

	var useRawCEK bool
	for _, builder := range ec.builders {
		if jwebb.IsDirectCEK(builder.alg.String()) {
			useRawCEK = true
			break
		}
	}

	lbuilders := len(ec.builders)
	recipients := recipientSlicePool.GetCapacity(lbuilders)
	defer recipientSlicePool.Put(recipients)

	for i, builder := range ec.builders {
		builder.pbes2Count = ec.pbes2Count
		r := recipientPool.Get()
		defer recipientPool.Put(r)

		rawCEK, err := builder.Build(r, cek, ec.calg)
		if err != nil {
			return nil, fmt.Errorf(`failed to create recipient #%d: %w`, i, err)
		}
		recipients = append(recipients, r)

		// Kinda feels weird, but if useRawCEK == true, we asserted earlier
		// that len(builders) == 1, so this is OK
		if useRawCEK {
			cek = rawCEK
		}
	}

	if len(cek) != contentcrypt.KeySize() {
		return nil, fmt.Errorf(`content encryption key length %d does not match enc %q (expected %d bytes)`, len(cek), ec.calg.String(), contentcrypt.KeySize())
	}

	if err := protected.setNoLock(ContentEncryptionKey, ec.calg); err != nil {
		return nil, fmt.Errorf(`failed to set "enc" in protected header: %w`, err)
	}

	if ec.compression != jwa.NoCompress() {
		payload, err = compress(payload)
		if err != nil {
			return nil, fmt.Errorf(`failed to compress payload before encryption: %w`, err)
		}
		if err := protected.setNoLock(CompressionKey, ec.compression); err != nil {
			return nil, fmt.Errorf(`failed to set "zip" in protected header: %w`, err)
		}
	}

	// fmtCompact does not have per-recipient headers, nor a "header" field.
	// In this mode, we're going to have to merge everything to the protected
	// header.
	if ec.format == fmtCompact {
		// We have already established that the number of builders is 1 in
		// ec.ProcessOptions(). But we're going to be pedantic
		if lbuilders != 1 {
			return nil, fmt.Errorf(`internal error: expected exactly one recipient builder (got %d)`, lbuilders)
		}

		// when we're using compact format, we can safely merge per-recipient
		// headers into the protected header in-place (we own it from pool).
		// Fast path: both are *stdHeaders owned exclusively, skip Keys/Field/Set overhead.
		if src, ok := recipients[0].Headers().(*stdHeaders); ok {
			src.mergeIntoNoLock(protected)
		} else if err := recipients[0].Headers().Copy(protected); err != nil {
			return nil, fmt.Errorf(`failed to merge protected headers for compact serialization: %w`, err)
		}
	} else {
		// If it got here, it's JSON (could be pretty mode, too).
		if lbuilders == 1 {
			// If it got here, then we're doing flattened JSON serialization.
			// In this mode, we should merge per-recipient headers into the protected header,
			// but we also need to make sure that the "header" field is reset so that
			// it does not contain the same fields as the protected header.
			merged, err := protected.Merge(recipients[0].Headers())
			if err != nil {
				return nil, fmt.Errorf(`failed to merge protected headers for flattenend JSON format: %w`, err)
			}
			protected, _ = merged.(*stdHeaders)

			if err := recipients[0].SetHeaders(NewHeaders()); err != nil {
				return nil, fmt.Errorf(`failed to clear per-recipient headers after merging: %w`, err)
			}
		}
	}

	aad, err := protected.Encode()
	if err != nil {
		return nil, fmt.Errorf(`failed to base64 encode protected headers: %w`, err)
	}

	iv, ciphertext, tag, err := contentcrypt.Encrypt(cek, payload, aad)
	if err != nil {
		return nil, fmt.Errorf(`failed to encrypt payload: %w`, err)
	}

	// For compact format, bypass Message construction entirely.
	// The protected header is already fully merged (per-recipient headers
	// were copied into protected above), so we can build the compact
	// serialization directly from the raw parts.
	if ec.format == fmtCompact {
		return jwebb.JoinCompact(base64.DefaultEncoder(), aad, recipients[0].EncryptedKey(), iv, ciphertext, tag), nil
	}

	msg := msgPool.Get()
	defer msgPool.Put(msg)

	if err := msg.Set(CipherTextKey, ciphertext); err != nil {
		return nil, fmt.Errorf(`failed to set %s: %w`, CipherTextKey, err)
	}
	if err := msg.Set(InitializationVectorKey, iv); err != nil {
		return nil, fmt.Errorf(`failed to set %s: %w`, InitializationVectorKey, err)
	}
	if err := msg.Set(ProtectedHeadersKey, protected); err != nil {
		return nil, fmt.Errorf(`failed to set %s: %w`, ProtectedHeadersKey, err)
	}
	if err := msg.Set(RecipientsKey, recipients); err != nil {
		return nil, fmt.Errorf(`failed to set %s: %w`, RecipientsKey, err)
	}
	if err := msg.Set(TagKey, tag); err != nil {
		return nil, fmt.Errorf(`failed to set %s: %w`, TagKey, err)
	}

	switch ec.format {
	case fmtJSON:
		return json.Marshal(msg)
	case fmtJSONPretty:
		return json.MarshalIndent(msg, "", "  ")
	default:
		return nil, fmt.Errorf(`invalid serialization`)
	}
}

// Decrypt takes encrypted payload, and information required to decrypt the
// payload (e.g. the key encryption algorithm and the corresponding
// key to decrypt the JWE message) in its optional arguments. See
// the examples and list of options that return a DecryptOption for possible
// values. Upon successful decryption returns the decrypted payload.
//
// The JWE message can be either compact or full JSON format.
//
// When using `jwe.WithKey()`, you can pass a `jwa.KeyAlgorithm`
// for convenience: this is mainly to allow you to directly pass the result of `(jwk.Key).Algorithm()`.
// However, do note that while `(jwk.Key).Algorithm()` could very well contain key encryption
// algorithms, it could also contain other types of values, such as _signature algorithms_.
// In order for `jwe.Decrypt` to work properly, the `alg` parameter must be of type
// `jwa.KeyEncryptionAlgorithm` or otherwise it will cause an error.
//
// When using `jwe.WithKey()`, the value must be a private key.
// It can be either in its raw format (e.g. *rsa.PrivateKey) or a jwk.Key
//
// When the encrypted message is also compressed, the decompressed payload must be
// smaller than the size specified by the `jwe.WithMaxDecompressBufferSize` setting,
// which defaults to 10MB. If the decompressed payload is larger than this size,
// an error is returned.
//
// You can opt to change the MaxDecompressBufferSize setting globally, or on a
// per-call basis by passing the `jwe.WithMaxDecompressBufferSize` option to
// either `jwe.Settings()` or `jwe.Decrypt()`:
//
//	jwe.Settings(jwe.WithMaxDecompressBufferSize(10*1024*1024)) // changes value globally
//	jwe.Decrypt(..., jwe.WithMaxDecompressBufferSize(250*1024)) // changes just for this call
//
// PBES2 amplification: PBES2 algorithms (PBES2-HS256+A128KW, etc.)
// derive the CEK via PBKDF2 with the iteration count taken from the
// JWE's `p2c` header. An attacker-controlled iteration count multiplied
// by `WithMaxRecipients` is the major CPU-amplification vector on the
// decrypt side. Bound it via `WithMaxPBES2Count` (default 1,000,000)
// and reject too-low counts via `WithMinPBES2Count` (default 1000;
// RFC 7518 §4.8.1.2 floor — note OWASP 2023 recommends ≥600,000 for
// production password-derived key material). Both options accept a
// `Settings()` global or a per-call value the same way
// `WithMaxDecompressBufferSize` does.
func Decrypt(buf []byte, options ...DecryptOption) ([]byte, error) {
	dc := decryptContextPool.Get()
	defer decryptContextPool.Put(dc)

	if err := dc.ProcessOptions(options); err != nil {
		return nil, makeDecryptError(`failed to process options: %w`, err)
	}

	ret, err := dc.DecryptMessage(buf)
	if err != nil {
		// DecryptMessage already returns errors prefixed with
		// "jwe.Decrypt:" — wrap as decryptError without adding a
		// second prefix, otherwise multi-recipient errors carry the
		// "jwe.Decrypt:" string R×K + 2 times in their message.
		return nil, decryptError{err}
	}
	return ret, nil
}

// Parse parses the JWE message into a Message object. The JWE message
// can be either compact or full JSON format.
//
// Bounding the input size is the caller's responsibility; this function
// trusts the caller-provided buf. See docs/13-input-size.md.
func Parse(buf []byte, _ ...ParseOption) (*Message, error) {
	return parseJSONOrCompact(buf, false, int(maxRecipients.Load()))
}

// errors are wrapped within this function, because we call it directly
// from Decrypt as well.
func parseJSONOrCompact(buf []byte, storeProtectedHeaders bool, maxR int) (*Message, error) {
	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return nil, makeParseError(`jwe.Parse`, `empty buffer`)
	}

	var msg *Message
	var err error
	if buf[0] == tokens.OpenCurlyBracket {
		msg, err = parseJSON(buf, storeProtectedHeaders)
	} else {
		msg, err = parseCompact(buf, storeProtectedHeaders)
	}

	if err != nil {
		return nil, makeParseError(`jwe.Parse`, `%w`, err)
	}

	if maxR > 0 && len(msg.recipients) > maxR {
		return nil, makeParseError(`jwe.Parse`, `too many recipients in JWE message (%d > %d)`, len(msg.recipients), maxR)
	}

	return msg, nil
}

// ParseString is the same as Parse, but takes a string.
func ParseString(s string, _ ...ParseOption) (*Message, error) {
	msg, err := Parse([]byte(s))
	if err != nil {
		return nil, makeParseError(`jwe.ParseString`, `%w`, err)
	}
	return msg, nil
}

// ParseReader is the same as Parse, but takes an io.Reader.
//
// Bounding the input size is the caller's responsibility: wrap src with
// [io.LimitReader] or [net/http.MaxBytesReader] before passing it in. See
// docs/13-input-size.md for the rationale.
func ParseReader(src io.Reader, _ ...ParseOption) (*Message, error) {
	buf, err := io.ReadAll(src)
	if err != nil {
		return nil, makeParseError(`jwe.ParseReader`, `failed to read from io.Reader: %w`, err)
	}
	msg, err := Parse(buf)
	if err != nil {
		return nil, makeParseError(`jwe.ParseReader`, `%w`, err)
	}
	return msg, nil
}

func parseJSON(buf []byte, storeProtectedHeaders bool) (*Message, error) {
	m := NewMessage()
	m.storeProtectedHeaders = storeProtectedHeaders
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, fmt.Errorf(`failed to parse JSON: %w`, err)
	}
	return m, nil
}

func parseCompact(buf []byte, storeProtectedHeaders bool) (*Message, error) {
	var parts [5][]byte
	var ok bool

	for i := range 4 {
		parts[i], buf, ok = bytes.Cut(buf, []byte{tokens.Period})
		if !ok {
			return nil, fmt.Errorf(`compact JWE format must have five parts (%d)`, i+1)
		}
	}
	// Validate that the last part does not contain more dots
	if bytes.ContainsRune(buf, tokens.Period) {
		return nil, errors.New(`compact JWE format must have five parts, not more`)
	}
	parts[4] = buf

	hdrbuf, err := base64.Decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf(`failed to parse first part of compact form: %w`, err)
	}

	protected := NewHeaders()
	if err := json.Unmarshal(hdrbuf, protected); err != nil {
		return nil, fmt.Errorf(`failed to parse header JSON: %w`, err)
	}

	ivbuf, err := base64.Decode(parts[2])
	if err != nil {
		return nil, fmt.Errorf(`failed to base64 decode iv: %w`, err)
	}

	ctbuf, err := base64.Decode(parts[3])
	if err != nil {
		return nil, fmt.Errorf(`failed to base64 decode content: %w`, err)
	}

	tagbuf, err := base64.Decode(parts[4])
	if err != nil {
		return nil, fmt.Errorf(`failed to base64 decode tag: %w`, err)
	}

	m := NewMessage()
	if err := m.Set(CipherTextKey, ctbuf); err != nil {
		return nil, fmt.Errorf(`failed to set %s: %w`, CipherTextKey, err)
	}
	if err := m.Set(InitializationVectorKey, ivbuf); err != nil {
		return nil, fmt.Errorf(`failed to set %s: %w`, InitializationVectorKey, err)
	}
	if err := m.Set(ProtectedHeadersKey, protected); err != nil {
		return nil, fmt.Errorf(`failed to set %s: %w`, ProtectedHeadersKey, err)
	}

	if err := m.makeDummyRecipient(string(parts[1]), protected); err != nil {
		return nil, fmt.Errorf(`failed to setup recipient: %w`, err)
	}

	if err := m.Set(TagKey, tagbuf); err != nil {
		return nil, fmt.Errorf(`failed to set %s: %w`, TagKey, err)
	}

	if storeProtectedHeaders {
		// This is later used for decryption.
		m.rawProtectedHeaders = parts[0]
	}

	return m, nil
}

// CustomDecoder is a generic interface for custom field decoders.
type CustomDecoder[T any] = json.CustomDecoder[T]

// CustomDecodeFunc is a function-based implementation of CustomDecoder[T].
type CustomDecodeFunc[T any] = json.CustomDecodeFunc[T]

// RegisterCustomField registers a private field to be decoded as type T
// using json.Unmarshal. This option has a global effect.
//
//	jwe.RegisterCustomField[time.Time](`x-birthday`)
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
//	jwe.RegisterCustomDecoder(`x-birthday`, jwe.CustomDecodeFunc[time.Time](func(data []byte) (time.Time, error) {
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
