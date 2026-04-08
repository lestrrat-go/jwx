//go:generate ../scripts/jwxcodegen.sh generate-headers -objects=objects.yml

// Package jwe implements JWE as described in https://tools.ietf.org/html/rfc7516
package jwe

// #region imports
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
var maxRecipients atomic.Int64
var maxDecompressBufferSize atomic.Int64
var maxParseInputSize atomic.Int64

func init() {
	maxPBES2Count.Store(10000)
	minPBES2Count.Store(1000)
	maxRecipients.Store(100)
	maxDecompressBufferSize.Store(10 * 1024 * 1024) // 10MB
	maxParseInputSize.Store(10 * 1024 * 1024)       // 10MB
}

func Settings(options ...GlobalOption) {
	for _, opt := range options {
		switch opt.Ident() {
		case identMaxPBES2Count{}:
			maxPBES2Count.Store(int64(option.MustGet[int](opt)))
		case identMinPBES2Count{}:
			minPBES2Count.Store(int64(option.MustGet[int](opt)))
		case identMaxRecipients{}:
			maxRecipients.Store(int64(option.MustGet[int](opt)))
		case identMaxDecompressBufferSize{}:
			maxDecompressBufferSize.Store(option.MustGet[int64](opt))
		case identCBCBufferSize{}:
			aescbc.SetMaxBufferSize(option.MustGet[int64](opt))
		case identMaxParseInputSize{}:
			v := option.MustGet[int64](opt)
			if v <= 0 {
				panic("jwe.Settings: WithMaxParseInputSize must be greater than zero")
			}
			maxParseInputSize.Store(v)
		}
	}
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
	alg     jwa.KeyEncryptionAlgorithm
	key     any
	headers Headers
}

func (b *recipientBuilder) Build(r Recipient, cek []byte, calg jwa.ContentEncryptionAlgorithm) ([]byte, error) {
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
			hdr = NewHeaders()
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
	}

	if val, ok := hdr.AgreementPartyUInfo(); ok {
		apu = val
	}

	if val, ok := hdr.AgreementPartyVInfo(); ok {
		apv = val
	}

	enc := newEncrypter(b.alg, calg, resolvedKey, apu, apv)

	_ = r.SetHeaders(hdr)

	// Populate headers with stuff that we automatically set
	if err := hdr.Set(AlgorithmKey, b.alg); err != nil {
		return nil, fmt.Errorf(`failed to set header: %w`, err)
	}

	if keyID != "" {
		if err := hdr.Set(KeyIDKey, keyID); err != nil {
			return nil, fmt.Errorf(`failed to set header: %w`, err)
		}
	}

	// Handle the encrypted key
	var rawCEK []byte
	enckey, err := enc.EncryptKey(cek)
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
//	jwe.Encrypt(payload, jws.WithJSON(), jws.WithKey(alg1, key1), jws.WithKey(alg2, key2))
//
// Note that in the second example the `jws.WithJSON()` option is
// specified as well. This is because the compact serialization
// format does not support multiple recipients, and users must
// specifically ask for the JSON serialization format.
//
// Read the documentation for `jwe.WithKey()` to learn more about the
// possible values that can be used for `alg` and `key`.
//
// Look for options that return `jwe.EncryptOption` or `jws.EncryptDecryptOption`
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
	//nolint:containedctx
	ctx context.Context
}

var decryptContextPool = pool.New(allocDecryptContext, freeDecryptContext)

func allocDecryptContext() *decryptContext {
	return &decryptContext{
		ctx: context.Background(),
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
		}
	}
	if ctxOpt != nil {
		dc.ctx = ctxOpt
	}

	if len(dc.keyProviders) < 1 {
		return fmt.Errorf(`jwe.Decrypt: no key providers have been provided (see jwe.WithKey(), jwe.WithKeySet(), and jwe.WithKeyProvider()`)
	}

	return nil
}

func (dc *decryptContext) DecryptMessage(buf []byte) ([]byte, error) {
	msg, err := parseJSONOrCompact(buf, true, dc.maxRecipients)
	if err != nil {
		return nil, fmt.Errorf(`failed to parse buffer for Decrypt: %w`, err)
	}

	// Process things that are common to the message
	h, err := msg.protectedHeaders.Clone()
	if err != nil {
		return nil, fmt.Errorf(`failed to copy protected headers: %w`, err)
	}
	h, err = h.Merge(msg.unprotectedHeaders)
	if err != nil {
		return nil, fmt.Errorf(`failed to merge headers for message decryption: %w`, err)
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
			return nil, fmt.Errorf(`failed to encode protected headers: %w`, err)
		}
	}

	// for each recipient, attempt to match the key providers
	// if we have no recipients, pretend like we only have one
	recipients := msg.recipients
	if len(recipients) == 0 {
		r := NewRecipient()
		if err := r.SetHeaders(msg.protectedHeaders); err != nil {
			return nil, fmt.Errorf(`failed to set headers to recipient: %w`, err)
		}
		recipients = append(recipients, r)
	}

	errs := make([]error, 0, len(recipients))
	for _, recipient := range recipients {
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
	return nil, fmt.Errorf(`failed to decrypt any of the recipients: %w`, errors.Join(errs...))
}

func (dc *decryptContext) tryRecipient(msg *Message, recipient Recipient, protectedHeaders Headers, aad, computedAad []byte) ([]byte, error) {
	var tried int
	var lastError error
	for i, kp := range dc.keyProviders {
		var sink algKeySink
		if err := kp.FetchKeys(dc.ctx, &sink, recipient, msg); err != nil {
			return nil, fmt.Errorf(`key provider %d failed: %w`, i, err)
		}

		for _, pair := range sink.list {
			tried++
			// alg is converted here because pair.alg is of type jwa.KeyAlgorithm.
			// this may seem ugly, but we're trying to avoid declaring separate
			// structs for `alg jwa.KeyEncryptionAlgorithm` and `alg jwa.SignatureAlgorithm`
			//nolint:forcetypeassert
			alg := pair.alg.(jwa.KeyEncryptionAlgorithm)
			key := pair.key

			decrypted, err := dc.decryptContent(msg, alg, key, recipient, protectedHeaders, aad, computedAad)
			if err != nil {
				lastError = err
				continue
			}

			if dc.keyUsed != nil {
				*dc.keyUsed = key
			}
			return decrypted, nil
		}
	}
	return nil, fmt.Errorf(`jwe.Decrypt: tried %d keys, but failed to match any of the keys with recipient (last error = %w)`, tried, lastError)
}

func (dc *decryptContext) decryptContent(msg *Message, alg jwa.KeyEncryptionAlgorithm, key any, recipient Recipient, protectedHeaders Headers, aad, computedAad []byte) ([]byte, error) {
	if jwkKey, ok := key.(jwk.Key); ok {
		raw, err := jwk.Export[any](jwkKey)
		if err != nil {
			return nil, fmt.Errorf(`failed to retrieve raw key from %T: %w`, key, err)
		}
		key = raw
	}

	ce, ok := msg.protectedHeaders.ContentEncryption()
	if !ok {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to retrieve content encryption algorithm from protected headers`)
	}

	// The "alg" header can be in either protected/unprotected headers.
	// prefer per-recipient headers (as it might be the case that the algorithm differs
	// by each recipient), then look at protected headers.
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
		return nil, fmt.Errorf(`jwe.Decrypt: key (%q) and recipient (%q) algorithms do not match`, alg, v)
	}
	if !algMatched {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to find "alg" header in either protected or per-recipient headers`)
	}

	// Merge protected and per-recipient headers for algorithm-specific param extraction
	h2, err := protectedHeaders.Clone()
	if err != nil {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to copy headers (1): %w`, err)
	}

	h2, err = h2.Merge(recipient.Headers())
	if err != nil {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to merge headers: %w`, err)
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
	cek, err := decryptCEK(alg, key, recipient, h2, cekCtx)
	if err != nil {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to decrypt key: %w`, err)
	}

	if dc.cek != nil {
		*dc.cek = cek
	}

	// Decrypt the payload
	computedAadFull := computedAad
	if aad != nil {
		computedAadFull = append(append(computedAadFull, tokens.Period), aad...)
	}

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

	return plaintext, nil
}

// encryptContext holds the state during JWE encryption, similar to JWS signContext
type encryptContext struct {
	calg        jwa.ContentEncryptionAlgorithm
	compression jwa.CompressionAlgorithm
	format      int
	builders    []*recipientBuilder
	protected   Headers
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
	ec.builders = ec.builders[:0]
	ec.protected = nil
	return ec
}

func (ec *encryptContext) ProcessOptions(options []EncryptOption) error {
	var mergeProtected bool
	var useRawCEK bool
	for _, opt := range options {
		switch opt.Ident() {
		case identKey{}:
			wk := option.MustGet[*withKey](opt)
			v, ok := wk.alg.(jwa.KeyEncryptionAlgorithm)
			if !ok {
				return fmt.Errorf("jwe.encrypt: WithKey() option must be specified using jwa.KeyEncryptionAlgorithm (got %T)", wk.alg)
			}
			if jwebb.IsDirectCEK(v.String()) {
				useRawCEK = true
			}
			ec.builders = append(ec.builders, &recipientBuilder{
				alg:     v,
				key:     wk.key,
				headers: wk.headers,
			})
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
		return fmt.Errorf(`missing key encryption builders: use jwe.WithKey() to specify one`)
	case l > 1:
		if ec.format == fmtCompact {
			return fmt.Errorf(`cannot use compact serialization when multiple recipients exist (check the number of WithKey() argument, or use WithJSON())`)
		}
	}

	if useRawCEK {
		if len(ec.builders) != 1 {
			return fmt.Errorf(`multiple recipients for ECDH-ES/DIRECT mode supported`)
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
	if h := r.Headers(); h != nil {
		if c, ok := h.(interface{ clear() }); ok {
			c.clear()
		}
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
	// Get protected headers from pool and copy contents from context
	protected := headerPool.Get()
	if userSupplied := ec.protected; userSupplied != nil {
		ec.protected = nil // Clear from context
		if err := userSupplied.Copy(protected); err != nil {
			return nil, fmt.Errorf(`failed to copy protected headers: %w`, err)
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

	if err := protected.Set(ContentEncryptionKey, ec.calg); err != nil {
		return nil, fmt.Errorf(`failed to set "enc" in protected header: %w`, err)
	}

	if ec.compression != jwa.NoCompress() {
		payload, err = compress(payload)
		if err != nil {
			return nil, fmt.Errorf(`failed to compress payload before encryption: %w`, err)
		}
		if err := protected.Set(CompressionKey, ec.compression); err != nil {
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
		// headers into the protected header, if any
		h, err := protected.Merge(recipients[0].Headers())
		if err != nil {
			return nil, fmt.Errorf(`failed to merge protected headers for compact serialization: %w`, err)
		}
		protected = h
		// per-recipient headers, if any, will be ignored in compact format
	} else {
		// If it got here, it's JSON (could be pretty mode, too).
		if lbuilders == 1 {
			// If it got here, then we're doing flattened JSON serialization.
			// In this mode, we should merge per-recipient headers into the protected header,
			// but we also need to make sure that the "header" field is reset so that
			// it does not contain the same fields as the protected header.
			h, err := protected.Merge(recipients[0].Headers())
			if err != nil {
				return nil, fmt.Errorf(`failed to merge protected headers for flattenend JSON format: %w`, err)
			}
			protected = h

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

	// Fast path for compact serialization: assemble directly from
	// pre-encoded headers and raw fields, avoiding the full Message
	// construction and redundant header re-encoding that Compact() does.
	if ec.format == fmtCompact {
		return compactSerialize(aad, recipients[0].EncryptedKey(), iv, ciphertext, tag), nil
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
// values. Upon successful decryptiond returns the decrypted payload.
//
// The JWE message can be either compact or full JSON format.
//
// When using `jwe.WithKeyEncryptionAlgorithm()`, you can pass a `jwa.KeyAlgorithm`
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
func Decrypt(buf []byte, options ...DecryptOption) ([]byte, error) {
	dc := decryptContextPool.Get()
	defer decryptContextPool.Put(dc)

	if err := dc.ProcessOptions(options); err != nil {
		return nil, makeDecryptError(`jwe.Decrypt`, `failed to process options: %w`, err)
	}

	ret, err := dc.DecryptMessage(buf)
	if err != nil {
		return nil, makeDecryptError(`jwe.Decrypt`, `%w`, err)
	}
	return ret, nil
}

// Parse parses the JWE message into a Message object. The JWE message
// can be either compact or full JSON format.
//
// Parse() currently does not process any options, but the API accepts
// them so that callers like ParseReader can forward their option lists
// without filtering. Options such as WithMaxParseInputSize are handled
// by ParseReader before the data reaches this function.
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
func ParseString(s string, options ...ParseOption) (*Message, error) {
	msg, err := Parse([]byte(s), options...)
	if err != nil {
		return nil, makeParseError(`jwe.ParseString`, `%w`, err)
	}
	return msg, nil
}

// ParseReader is the same as Parse, but takes an io.Reader.
func ParseReader(src io.Reader, options ...ParseOption) (*Message, error) {
	maxSize := maxParseInputSize.Load()

	for _, opt := range options {
		if opt.Ident() == (identMaxParseInputSize{}) {
			maxSize = option.MustGet[int64](opt)
			if maxSize <= 0 {
				return nil, makeParseError(`jwe.ParseReader`, `WithMaxParseInputSize must be greater than zero`)
			}
		}
	}

	buf, err := io.ReadAll(io.LimitReader(src, maxSize+1))
	if err != nil {
		return nil, makeParseError(`jwe.ParseReader`, `failed to read from io.Reader: %w`, err)
	}
	if int64(len(buf)) > maxSize {
		return nil, makeParseError(`jwe.ParseReader`, `input exceeded max size of %d bytes`, maxSize)
	}
	msg, err := Parse(buf, options...)
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
func RegisterCustomField[T any](name string) {
	json.RegisterTyped[T](registry, name)
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
func RegisterCustomDecoder[T any](name string, dec CustomDecodeFunc[T]) {
	json.RegisterCustomDecoder[T](registry, name, dec)
}

// UnregisterCustomField removes the registration for a custom field.
func UnregisterCustomField(name string) {
	registry.Unregister(name)
}
