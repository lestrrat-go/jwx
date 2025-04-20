//go:generate ../tools/cmd/genjwe.sh

// Package jwe implements JWE as described in https://tools.ietf.org/html/rfc7516
package jwe

// #region imports
import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe/internal/aescbc"
	"github.com/lestrrat-go/jwx/v3/jwe/internal/content_crypt"
	"github.com/lestrrat-go/jwx/v3/jwe/internal/keyenc"
	"github.com/lestrrat-go/jwx/v3/jwe/internal/keygen"
)

// #region globals

var muSettings sync.RWMutex
var maxPBES2Count = 10000
var maxDecompressBufferSize int64 = 10 * 1024 * 1024 // 10MB

func Settings(options ...GlobalOption) {
	muSettings.Lock()
	defer muSettings.Unlock()
	//nolint:forcetypeassert
	for _, option := range options {
		switch option.Ident() {
		case identMaxPBES2Count{}:
			maxPBES2Count = option.Value().(int)
		case identMaxDecompressBufferSize{}:
			maxDecompressBufferSize = option.Value().(int64)
		case identCBCBufferSize{}:
			aescbc.SetMaxBufferSize(option.Value().(int64))
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

var _ = fmtInvalid
var _ = fmtMax

var registry = json.NewRegistry()

type keyEncrypterWrapper struct {
	encrypter KeyEncrypter
}

func (w *keyEncrypterWrapper) Algorithm() jwa.KeyEncryptionAlgorithm {
	return w.encrypter.Algorithm()
}

func (w *keyEncrypterWrapper) EncryptKey(cek []byte) (keygen.ByteSource, error) {
	encrypted, err := w.encrypter.EncryptKey(cek)
	if err != nil {
		return nil, err
	}
	return keygen.ByteKey(encrypted), nil
}

type recipientBuilder struct {
	alg     jwa.KeyEncryptionAlgorithm
	key     interface{}
	headers Headers
}

func (b *recipientBuilder) Build(cek []byte, calg jwa.ContentEncryptionAlgorithm, cc *content_crypt.Generic) (Recipient, []byte, error) {
	var enc keyenc.Encrypter

	// we need the raw key for later use
	rawKey := b.key

	var keyID string
	if ke, ok := b.key.(KeyEncrypter); ok {
		enc = &keyEncrypterWrapper{encrypter: ke}
		if kider, ok := enc.(KeyIDer); ok {
			if v, ok := kider.KeyID(); ok {
				keyID = v
			}
		}
	} else if jwkKey, ok := b.key.(jwk.Key); ok {
		// Meanwhile, grab the kid as well
		if v, ok := jwkKey.KeyID(); ok {
			keyID = v
		}

		var raw interface{}
		if err := jwk.Export(jwkKey, &raw); err != nil {
			return nil, nil, fmt.Errorf(`failed to retrieve raw key out of %T: %w`, b.key, err)
		}

		rawKey = raw
	}

	if enc == nil {
		switch b.alg {
		case jwa.RSA1_5():
			var pubkey rsa.PublicKey
			if err := keyconv.RSAPublicKey(&pubkey, rawKey); err != nil {
				return nil, nil, fmt.Errorf(`failed to generate public key from key (%T): %w`, rawKey, err)
			}

			v, err := keyenc.NewRSAPKCSEncrypt(b.alg, &pubkey)
			if err != nil {
				return nil, nil, fmt.Errorf(`failed to create RSA PKCS encrypter: %w`, err)
			}
			enc = v
		case jwa.RSA_OAEP(), jwa.RSA_OAEP_256(), jwa.RSA_OAEP_384(), jwa.RSA_OAEP_512():
			var pubkey rsa.PublicKey
			if err := keyconv.RSAPublicKey(&pubkey, rawKey); err != nil {
				return nil, nil, fmt.Errorf(`failed to generate public key from key (%T): %w`, rawKey, err)
			}

			v, err := keyenc.NewRSAOAEPEncrypt(b.alg, &pubkey)
			if err != nil {
				return nil, nil, fmt.Errorf(`failed to create RSA OAEP encrypter: %w`, err)
			}
			enc = v
		case jwa.A128KW(), jwa.A192KW(), jwa.A256KW(),
			jwa.A128GCMKW(), jwa.A192GCMKW(), jwa.A256GCMKW(),
			jwa.PBES2_HS256_A128KW(), jwa.PBES2_HS384_A192KW(), jwa.PBES2_HS512_A256KW():
			sharedkey, ok := rawKey.([]byte)
			if !ok {
				return nil, nil, fmt.Errorf(`invalid key: []byte required (%T)`, rawKey)
			}

			var err error
			switch b.alg {
			case jwa.A128KW(), jwa.A192KW(), jwa.A256KW():
				enc, err = keyenc.NewAES(b.alg, sharedkey)
			case jwa.PBES2_HS256_A128KW(), jwa.PBES2_HS384_A192KW(), jwa.PBES2_HS512_A256KW():
				enc, err = keyenc.NewPBES2Encrypt(b.alg, sharedkey)
			default:
				enc, err = keyenc.NewAESGCMEncrypt(b.alg, sharedkey)
			}
			if err != nil {
				return nil, nil, fmt.Errorf(`failed to create key wrap encrypter: %w`, err)
			}
			// NOTE: there was formerly a restriction, introduced
			// in PR #26, which disallowed certain key/content
			// algorithm combinations. This seemed bogus, and
			// interop with the jose tool demonstrates it.
		case jwa.ECDH_ES(), jwa.ECDH_ES_A128KW(), jwa.ECDH_ES_A192KW(), jwa.ECDH_ES_A256KW():
			var keysize int
			switch b.alg {
			case jwa.ECDH_ES():
				// https://tools.ietf.org/html/rfc7518#page-15
				// In Direct Key Agreement mode, the output of the Concat KDF MUST be a
				// key of the same length as that used by the "enc" algorithm.
				keysize = cc.KeySize()
			case jwa.ECDH_ES_A128KW():
				keysize = 16
			case jwa.ECDH_ES_A192KW():
				keysize = 24
			case jwa.ECDH_ES_A256KW():
				keysize = 32
			}

			switch key := rawKey.(type) {
			case *ecdh.PublicKey:
				var apu, apv []byte
				if hdrs := b.headers; hdrs != nil {
					if v, ok := hdrs.AgreementPartyUInfo(); ok {
						apu = v
					}
					if v, ok := hdrs.AgreementPartyVInfo(); ok {
						apv = v
					}
				}

				v, err := keyenc.NewECDHESEncrypt(b.alg, calg, keysize, rawKey, apu, apv)
				if err != nil {
					return nil, nil, fmt.Errorf(`failed to create ECDHS key wrap encrypter: %w`, err)
				}
				enc = v
			default:
				var pubkey ecdsa.PublicKey
				if err := keyconv.ECDSAPublicKey(&pubkey, rawKey); err != nil {
					return nil, nil, fmt.Errorf(`failed to generate public key from key (%T): %w`, key, err)
				}

				var apu, apv []byte
				if hdrs := b.headers; hdrs != nil {
					if v, ok := hdrs.AgreementPartyUInfo(); ok {
						apu = v
					}

					if v, ok := hdrs.AgreementPartyVInfo(); ok {
						apv = v
					}
				}

				v, err := keyenc.NewECDHESEncrypt(b.alg, calg, keysize, &pubkey, apu, apv)
				if err != nil {
					return nil, nil, fmt.Errorf(`failed to create ECDHS key wrap encrypter: %w`, err)
				}
				enc = v
			}
		case jwa.DIRECT():
			sharedkey, ok := rawKey.([]byte)
			if !ok {
				return nil, nil, fmt.Errorf("invalid key: []byte required")
			}
			enc, _ = keyenc.NewNoop(b.alg, sharedkey)
		default:
			return nil, nil, fmt.Errorf(`invalid key encryption algorithm (%s)`, b.alg)
		}
	}

	r := NewRecipient()
	if hdrs := b.headers; hdrs != nil {
		_ = r.SetHeaders(hdrs)
	}

	if err := r.Headers().Set(AlgorithmKey, b.alg); err != nil {
		return nil, nil, fmt.Errorf(`failed to set header: %w`, err)
	}

	if keyID != "" {
		if err := r.Headers().Set(KeyIDKey, keyID); err != nil {
			return nil, nil, fmt.Errorf(`failed to set header: %w`, err)
		}
	}

	var rawCEK []byte
	enckey, err := enc.EncryptKey(cek)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to encrypt key: %w`, err)
	}
	if enc.Algorithm() == jwa.ECDH_ES() || enc.Algorithm() == jwa.DIRECT() {
		rawCEK = enckey.Bytes()
	} else {
		if err := r.SetEncryptedKey(enckey.Bytes()); err != nil {
			return nil, nil, fmt.Errorf(`failed to set encrypted key: %w`, err)
		}
	}

	if hp, ok := enckey.(populater); ok {
		if err := hp.Populate(r.Headers()); err != nil {
			return nil, nil, fmt.Errorf(`failed to populate: %w`, err)
		}
	}

	return r, rawCEK, nil
}

// Encrypt generates a JWE message for the given payload and returns
// it in serialized form, which can be in either compact or
// JSON format. Default is compact.
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
	ret, err := encrypt(payload, nil, options...)
	if err != nil {
		return nil, encryptError{fmt.Errorf(`jwe.Encrypt: %w`, err)}
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
		return nil, encryptError{fmt.Errorf(`jwe.EncryptStatic: empty CEK`)}
	}
	ret, err := encrypt(payload, cek, options...)
	if err != nil {
		return nil, encryptError{fmt.Errorf(`jwe.EncryptStatic: %w`, err)}
	}
	return ret, nil
}

// encrypt is separate, so it can receive cek from outside.
// (but we don't want to receive it in the options slice)
func encrypt(payload, cek []byte, options ...EncryptOption) ([]byte, error) {
	// default content encryption algorithm
	calg := jwa.A256GCM()

	// default compression is "none"
	compression := jwa.NoCompress()

	// default format is compact serialization
	format := fmtCompact

	// builds each "recipient" with encrypted_key and headers
	var builders []*recipientBuilder

	var protected Headers
	var mergeProtected bool
	var useRawCEK bool
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identKey{}:
			data := option.Value().(*withKey)
			v, ok := data.alg.(jwa.KeyEncryptionAlgorithm)
			if !ok {
				return nil, fmt.Errorf(`expected alg to be jwa.KeyEncryptionAlgorithm, but got %T`, data.alg)
			}

			switch v {
			case jwa.DIRECT(), jwa.ECDH_ES():
				useRawCEK = true
			}

			builders = append(builders, &recipientBuilder{
				alg:     v,
				key:     data.key,
				headers: data.headers,
			})
		case identContentEncryptionAlgorithm{}:
			calg = option.Value().(jwa.ContentEncryptionAlgorithm)
		case identCompress{}:
			compression = option.Value().(jwa.CompressionAlgorithm)
		case identMergeProtectedHeaders{}:
			mergeProtected = option.Value().(bool)
		case identProtectedHeaders{}:
			v := option.Value().(Headers)
			if !mergeProtected || protected == nil {
				protected = v
			} else {
				merged, err := protected.Merge(v)
				if err != nil {
					return nil, fmt.Errorf(`failed to merge headers: %w`, err)
				}
				protected = merged
			}
		case identSerialization{}:
			format = option.Value().(int)
		}
	}

	// We need to have at least one builder
	switch l := len(builders); {
	case l == 0:
		return nil, fmt.Errorf(`missing key encryption builders: use jwe.WithKey() to specify one`)
	case l > 1:
		if format == fmtCompact {
			return nil, fmt.Errorf(`cannot use compact serialization when multiple recipients exist (check the number of WithKey() argument, or use WithJSON())`)
		}
	}

	if useRawCEK {
		if len(builders) != 1 {
			return nil, fmt.Errorf(`multiple recipients for ECDH-ES/DIRECT mode supported`)
		}
	}

	// There is exactly one content encrypter.
	contentcrypt, err := content_crypt.NewGeneric(calg)
	if err != nil {
		return nil, fmt.Errorf(`failed to create AES encrypter: %w`, err)
	}

	if len(cek) <= 0 {
		generator := keygen.NewRandom(contentcrypt.KeySize())
		bk, err := generator.Generate()
		if err != nil {
			return nil, fmt.Errorf(`failed to generate key: %w`, err)
		}
		cek = bk.Bytes()
	}

	recipients := make([]Recipient, len(builders))
	for i, builder := range builders {
		// some builders require hint from the contentcrypt object
		r, rawCEK, err := builder.Build(cek, calg, contentcrypt)
		if err != nil {
			return nil, fmt.Errorf(`failed to create recipient #%d: %w`, i, err)
		}
		recipients[i] = r

		// Kinda feels weird, but if useRawCEK == true, we asserted earlier
		// that len(builders) == 1, so this is OK
		if useRawCEK {
			cek = rawCEK
		}
	}

	if protected == nil {
		protected = NewHeaders()
	}

	if err := protected.Set(ContentEncryptionKey, calg); err != nil {
		return nil, fmt.Errorf(`failed to set "enc" in protected header: %w`, err)
	}

	if compression != jwa.NoCompress() {
		payload, err = compress(payload)
		if err != nil {
			return nil, fmt.Errorf(`failed to compress payload before encryption: %w`, err)
		}
		if err := protected.Set(CompressionKey, compression); err != nil {
			return nil, fmt.Errorf(`failed to set "zip" in protected header: %w`, err)
		}
	}

	// If there's only one recipient, you want to include that in the
	// protected header
	if len(recipients) == 1 {
		h, err := protected.Merge(recipients[0].Headers())
		if err != nil {
			return nil, fmt.Errorf(`failed to merge protected headers: %w`, err)
		}
		protected = h
	}

	aad, err := protected.Encode()
	if err != nil {
		return nil, fmt.Errorf(`failed to base64 encode protected headers: %w`, err)
	}

	iv, ciphertext, tag, err := contentcrypt.Encrypt(cek, payload, aad)
	if err != nil {
		return nil, fmt.Errorf(`failed to encrypt payload: %w`, err)
	}

	msg := NewMessage()

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

	switch format {
	case fmtCompact:
		return Compact(msg)
	case fmtJSON:
		return json.Marshal(msg)
	case fmtJSONPretty:
		return json.MarshalIndent(msg, "", "  ")
	default:
		return nil, fmt.Errorf(`invalid serialization`)
	}
}

type decryptCtx struct {
	msg                     *Message
	aad                     []byte
	cek                     *[]byte
	computedAad             []byte
	keyProviders            []KeyProvider
	protectedHeaders        Headers
	maxDecompressBufferSize int64
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
	ret, err := decrypt(buf, options...)
	if err != nil {
		return nil, decryptError{fmt.Errorf(`jwe.Decrypt: %w`, err)}
	}
	return ret, nil
}

func decrypt(buf []byte, options ...DecryptOption) ([]byte, error) {
	var keyProviders []KeyProvider
	var keyUsed interface{}
	var cek *[]byte
	var dst *Message
	perCallMaxDecompressBufferSize := maxDecompressBufferSize
	ctx := context.Background()
	//nolint:forcetypeassert
	for _, option := range options {
		switch option.Ident() {
		case identMessage{}:
			dst = option.Value().(*Message)
		case identKeyProvider{}:
			keyProviders = append(keyProviders, option.Value().(KeyProvider))
		case identKeyUsed{}:
			keyUsed = option.Value()
		case identKey{}:
			pair := option.Value().(*withKey)
			alg, ok := pair.alg.(jwa.KeyEncryptionAlgorithm)
			if !ok {
				return nil, fmt.Errorf(`WithKey() option must be specified using jwa.KeyEncryptionAlgorithm (got %T)`, pair.alg)
			}
			keyProviders = append(keyProviders, &staticKeyProvider{
				alg: alg,
				key: pair.key,
			})
		case identCEK{}:
			cek = option.Value().(*[]byte)
		case identMaxDecompressBufferSize{}:
			perCallMaxDecompressBufferSize = option.Value().(int64)
		case identContext{}:
			//nolint:fatcontext
			ctx = option.Value().(context.Context)
		}
	}

	if len(keyProviders) < 1 {
		return nil, fmt.Errorf(`jwe.Decrypt: no key providers have been provided (see jwe.WithKey(), jwe.WithKeySet(), and jwe.WithKeyProvider()`)
	}

	msg, err := parseJSONOrCompact(buf, true)
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

	var dctx decryptCtx

	dctx.aad = aad
	dctx.computedAad = computedAad
	dctx.msg = msg
	dctx.keyProviders = keyProviders
	dctx.protectedHeaders = h
	dctx.cek = cek
	dctx.maxDecompressBufferSize = perCallMaxDecompressBufferSize

	errs := make([]error, 0, len(recipients))
	for _, recipient := range recipients {
		decrypted, err := dctx.try(ctx, recipient, keyUsed)
		if err != nil {
			errs = append(errs, recipientError{err})
			continue
		}
		if dst != nil {
			*dst = *msg
			dst.rawProtectedHeaders = nil
			dst.storeProtectedHeaders = false
		}
		return decrypted, nil
	}
	return nil, fmt.Errorf(`failed to decrypt any of the recipients: %w`, errors.Join(errs...))
}

func (dctx *decryptCtx) try(ctx context.Context, recipient Recipient, keyUsed interface{}) ([]byte, error) {
	var tried int
	var lastError error
	for i, kp := range dctx.keyProviders {
		var sink algKeySink
		if err := kp.FetchKeys(ctx, &sink, recipient, dctx.msg); err != nil {
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

			decrypted, err := dctx.decryptContent(alg, key, recipient)
			if err != nil {
				lastError = err
				continue
			}

			if keyUsed != nil {
				if err := blackmagic.AssignIfCompatible(keyUsed, key); err != nil {
					return nil, fmt.Errorf(`failed to assign used key (%T) to %T: %w`, key, keyUsed, err)
				}
			}
			return decrypted, nil
		}
	}
	return nil, fmt.Errorf(`jwe.Decrypt: tried %d keys, but failed to match any of the keys with recipient (last error = %s)`, tried, lastError)
}

func (dctx *decryptCtx) decryptContent(alg jwa.KeyEncryptionAlgorithm, key interface{}, recipient Recipient) ([]byte, error) {
	if jwkKey, ok := key.(jwk.Key); ok {
		var raw interface{}
		if err := jwk.Export(jwkKey, &raw); err != nil {
			return nil, fmt.Errorf(`failed to retrieve raw key from %T: %w`, key, err)
		}
		key = raw
	}

	ce, ok := dctx.msg.protectedHeaders.ContentEncryption()
	if !ok {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to retrieve content encryption algorithm from protected headers`)
	}
	dec := newDecrypter(alg, ce, key).
		AuthenticatedData(dctx.aad).
		ComputedAuthenticatedData(dctx.computedAad).
		InitializationVector(dctx.msg.initializationVector).
		Tag(dctx.msg.tag).
		CEK(dctx.cek)

	if v, ok := recipient.Headers().Algorithm(); !ok || v != alg {
		// algorithms don't match
		return nil, fmt.Errorf(`jwe.Decrypt: key and recipient algorithms do not match`)
	}

	h2, err := dctx.protectedHeaders.Clone()
	if err != nil {
		return nil, fmt.Errorf(`jwe.Decrypt: failed to copy headers (1): %w`, err)
	}

	h2, err = h2.Merge(recipient.Headers())
	if err != nil {
		return nil, fmt.Errorf(`failed to copy headers (2): %w`, err)
	}

	switch alg {
	case jwa.ECDH_ES(), jwa.ECDH_ES_A128KW(), jwa.ECDH_ES_A192KW(), jwa.ECDH_ES_A256KW():
		var epk interface{}
		if err := h2.Get(EphemeralPublicKeyKey, &epk); err != nil {
			return nil, fmt.Errorf(`failed to get 'epk' field: %w`, err)
		}
		switch epk := epk.(type) {
		case jwk.ECDSAPublicKey:
			var pubkey ecdsa.PublicKey
			if err := jwk.Export(epk, &pubkey); err != nil {
				return nil, fmt.Errorf(`failed to get public key: %w`, err)
			}
			dec.PublicKey(&pubkey)
		case jwk.OKPPublicKey:
			var pubkey interface{}
			if err := jwk.Export(epk, &pubkey); err != nil {
				return nil, fmt.Errorf(`failed to get public key: %w`, err)
			}
			dec.PublicKey(pubkey)
		default:
			return nil, fmt.Errorf("unexpected 'epk' type %T for alg %s", epk, alg)
		}

		if apu, ok := h2.AgreementPartyUInfo(); ok && len(apu) > 0 {
			dec.AgreementPartyUInfo(apu)
		}
		if apv, ok := h2.AgreementPartyVInfo(); ok && len(apv) > 0 {
			dec.AgreementPartyVInfo(apv)
		}
	case jwa.A128GCMKW(), jwa.A192GCMKW(), jwa.A256GCMKW():
		var ivB64 string
		if err := h2.Get(InitializationVectorKey, &ivB64); err == nil {
			iv, err := base64.DecodeString(ivB64)
			if err != nil {
				return nil, fmt.Errorf(`failed to b64-decode 'iv': %w`, err)
			}
			dec.KeyInitializationVector(iv)
		}
		var tagB64 string
		if err := h2.Get(TagKey, &tagB64); err == nil {
			tag, err := base64.DecodeString(tagB64)
			if err != nil {
				return nil, fmt.Errorf(`failed to b64-decode 'tag': %w`, err)
			}
			dec.KeyTag(tag)
		}
	case jwa.PBES2_HS256_A128KW(), jwa.PBES2_HS384_A192KW(), jwa.PBES2_HS512_A256KW():
		var saltB64 string
		if err := h2.Get(SaltKey, &saltB64); err != nil {
			return nil, fmt.Errorf(`failed to get %q field`, SaltKey)
		}

		// check if WithUseNumber is effective, because it will change the
		// type of the underlying value (#1140)
		var countFlt float64
		if json.UseNumber() {
			var count json.Number
			if err := h2.Get(CountKey, &count); err != nil {
				return nil, fmt.Errorf(`failed to get %q field`, CountKey)
			}
			v, err := count.Float64()
			if err != nil {
				return nil, fmt.Errorf("failed to convert 'p2c' to float64: %w", err)
			}
			countFlt = v
		} else {
			var count float64
			if err := h2.Get(CountKey, &count); err != nil {
				return nil, fmt.Errorf(`failed to get %q field`, CountKey)
			}
			countFlt = count
		}

		muSettings.RLock()
		maxCount := maxPBES2Count
		muSettings.RUnlock()
		if countFlt > float64(maxCount) {
			return nil, fmt.Errorf("invalid 'p2c' value")
		}
		salt, err := base64.DecodeString(saltB64)
		if err != nil {
			return nil, fmt.Errorf(`failed to b64-decode 'salt': %w`, err)
		}
		dec.KeySalt(salt)
		dec.KeyCount(int(countFlt))
	}

	plaintext, err := dec.Decrypt(recipient, dctx.msg.cipherText, dctx.msg)
	if err != nil {
		return nil, fmt.Errorf(`jwe.Decrypt: decryption failed: %w`, err)
	}

	if v, ok := h2.Compression(); ok && v == jwa.Deflate() {
		buf, err := uncompress(plaintext, dctx.maxDecompressBufferSize)
		if err != nil {
			return nil, fmt.Errorf(`jwe.Derypt: failed to uncompress payload: %w`, err)
		}
		plaintext = buf
	}

	if plaintext == nil {
		return nil, fmt.Errorf(`failed to find matching recipient`)
	}

	return plaintext, nil
}

// Parse parses the JWE message into a Message object. The JWE message
// can be either compact or full JSON format.
//
// Parse() currently does not take any options, but the API accepts it
// in anticipation of future addition.
func Parse(buf []byte, _ ...ParseOption) (*Message, error) {
	return parseJSONOrCompact(buf, false)
}

// errors are wrapped within this function, because we call it directly
// from Decrypt as well.
func parseJSONOrCompact(buf []byte, storeProtectedHeaders bool) (*Message, error) {
	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return nil, parseError{fmt.Errorf(`jwe.Parse: empty buffer`)}
	}

	var msg *Message
	var err error
	if buf[0] == '{' {
		msg, err = parseJSON(buf, storeProtectedHeaders)
	} else {
		msg, err = parseCompact(buf, storeProtectedHeaders)
	}

	if err != nil {
		return nil, parseError{fmt.Errorf(`jwe.Parse: %w`, err)}
	}
	return msg, nil
}

// ParseString is the same as Parse, but takes a string.
func ParseString(s string) (*Message, error) {
	msg, err := Parse([]byte(s))
	if err != nil {
		return nil, parseError{fmt.Errorf(`jwe.ParseString: %w`, err)}
	}
	return msg, nil
}

// ParseReader is the same as Parse, but takes an io.Reader.
func ParseReader(src io.Reader) (*Message, error) {
	buf, err := io.ReadAll(src)
	if err != nil {
		return nil, parseError{fmt.Errorf(`jwe.ParseReader: failed to read from io.Reader: %w`, err)}
	}
	msg, err := Parse(buf)
	if err != nil {
		return nil, parseError{fmt.Errorf(`jwe.ParseReader: %w`, err)}
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
		parts[i], buf, ok = bytes.Cut(buf, []byte{'.'})
		if !ok {
			return nil, fmt.Errorf(`compact JWE format must have five parts (%d)`, i+1)
		}
	}
	// Validate that the last part does not contain more dots
	if bytes.ContainsRune(buf, '.') {
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

type CustomDecoder = json.CustomDecoder
type CustomDecodeFunc = json.CustomDecodeFunc

// RegisterCustomField allows users to specify that a private field
// be decoded as an instance of the specified type. This option has
// a global effect.
//
// For example, suppose you have a custom field `x-birthday`, which
// you want to represent as a string formatted in RFC3339 in JSON,
// but want it back as `time.Time`.
//
// In such case you would register a custom field as follows
//
//	jws.RegisterCustomField(`x-birthday`, time.Time{})
//
// Then you can use a `time.Time` variable to extract the value
// of `x-birthday` field, instead of having to use `interface{}`
// and later convert it to `time.Time`
//
//	var bday time.Time
//	_ = hdr.Get(`x-birthday`, &bday)
//
// If you need a more fine-tuned control over the decoding process,
// you can register a `CustomDecoder`. For example, below shows
// how to register a decoder that can parse RFC1123 format string:
//
//	jwe.RegisterCustomField(`x-birthday`, jwe.CustomDecodeFunc(func(data []byte) (interface{}, error) {
//	  return time.Parse(time.RFC1123, string(data))
//	}))
//
// Please note that use of custom fields can be problematic if you
// are using a library that does not implement MarshalJSON/UnmarshalJSON
// and you try to roundtrip from an object to JSON, and then back to an object.
// For example, in the above example, you can _parse_ time values formatted
// in the format specified in RFC822, but when you convert an object into
// JSON, it will be formatted in RFC3339, because that's what `time.Time`
// likes to do. To avoid this, it's always better to use a custom type
// that wraps your desired type (in this case `time.Time`) and implement
// MarshalJSON and UnmashalJSON.
func RegisterCustomField(name string, object interface{}) {
	registry.Register(name, object)
}
