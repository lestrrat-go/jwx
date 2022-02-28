//go:generate ./gen.sh

// Package jwe implements JWE as described in https://tools.ietf.org/html/rfc7516
package jwe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/internal/keyconv"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/internal/content_crypt"
	"github.com/lestrrat-go/jwx/jwe/internal/keyenc"
	"github.com/lestrrat-go/jwx/jwe/internal/keygen"
	"github.com/lestrrat-go/jwx/x25519"
	"github.com/pkg/errors"
)

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

type recipientBuilder struct {
	alg     jwa.KeyEncryptionAlgorithm
	key     interface{}
	headers Headers
}

func (b *recipientBuilder) Build(cek []byte, calg jwa.ContentEncryptionAlgorithm, cc *content_crypt.Generic) (Recipient, []byte, error) {
	// we need the raw key
	rawKey := b.key

	var keyID string
	if jwkKey, ok := b.key.(jwk.Key); ok {
		// Meanwhile, grab the kid as well
		keyID = jwkKey.KeyID()

		var raw interface{}
		if err := jwkKey.Raw(&raw); err != nil {
			return nil, nil, fmt.Errorf(`failed to retrieve raw key out of %T: %w`, b.key, err)
		}

		rawKey = raw
	}

	// First, create a key encryptor
	var enc keyenc.Encrypter
	switch b.alg {
	case jwa.RSA1_5:
		var pubkey rsa.PublicKey
		if err := keyconv.RSAPublicKey(&pubkey, rawKey); err != nil {
			return nil, nil, fmt.Errorf(`failed to generate public key from key (%T): %w`, rawKey, err)
		}

		v, err := keyenc.NewRSAPKCSEncrypt(b.alg, &pubkey)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to create RSA PKCS encrypter: %w`, err)
		}
		enc = v
	case jwa.RSA_OAEP, jwa.RSA_OAEP_256:
		var pubkey rsa.PublicKey
		if err := keyconv.RSAPublicKey(&pubkey, rawKey); err != nil {
			return nil, nil, fmt.Errorf(`failed to generate public key from key (%T): %w`, rawKey, err)
		}

		v, err := keyenc.NewRSAOAEPEncrypt(b.alg, &pubkey)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to create RSA OAEP encrypter: %w`, err)
		}
		enc = v
	case jwa.A128KW, jwa.A192KW, jwa.A256KW,
		jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW,
		jwa.PBES2_HS256_A128KW, jwa.PBES2_HS384_A192KW, jwa.PBES2_HS512_A256KW:
		sharedkey, ok := rawKey.([]byte)
		if !ok {
			return nil, nil, fmt.Errorf(`invalid key: []byte required (%T)`, rawKey)
		}

		var err error
		switch b.alg {
		case jwa.A128KW, jwa.A192KW, jwa.A256KW:
			enc, err = keyenc.NewAES(b.alg, sharedkey)
		case jwa.PBES2_HS256_A128KW, jwa.PBES2_HS384_A192KW, jwa.PBES2_HS512_A256KW:
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
	case jwa.ECDH_ES, jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
		var keysize int
		switch b.alg {
		case jwa.ECDH_ES:
			// https://tools.ietf.org/html/rfc7518#page-15
			// In Direct Key Agreement mode, the output of the Concat KDF MUST be a
			// key of the same length as that used by the "enc" algorithm.
			keysize = cc.KeySize()
		case jwa.ECDH_ES_A128KW:
			keysize = 16
		case jwa.ECDH_ES_A192KW:
			keysize = 24
		case jwa.ECDH_ES_A256KW:
			keysize = 32
		}

		switch key := rawKey.(type) {
		case x25519.PublicKey:
			v, err := keyenc.NewECDHESEncrypt(b.alg, calg, keysize, rawKey)
			if err != nil {
				return nil, nil, fmt.Errorf(`failed to create ECDHS key wrap encrypter: %w`, err)
			}
			enc = v
		default:
			var pubkey ecdsa.PublicKey
			if err := keyconv.ECDSAPublicKey(&pubkey, rawKey); err != nil {
				return nil, nil, fmt.Errorf(`failed to generate public key from key (%T): %w`, key, err)
			}
			v, err := keyenc.NewECDHESEncrypt(b.alg, calg, keysize, &pubkey)
			if err != nil {
				return nil, nil, fmt.Errorf(`failed to create ECDHS key wrap encrypter: %w`, err)
			}
			enc = v
		}
	case jwa.DIRECT:
		sharedkey, ok := rawKey.([]byte)
		if !ok {
			return nil, nil, fmt.Errorf("invalid key: []byte required")
		}
		enc, _ = keyenc.NewNoop(b.alg, sharedkey)
	default:
		return nil, nil, fmt.Errorf(`invalid key encryption algorithm (%s)`, b.alg)
	}

	if keyID != "" {
		enc.SetKeyID(keyID)
	}

	r := NewRecipient()

	if err := r.Headers().Set(AlgorithmKey, b.alg); err != nil {
		return nil, nil, fmt.Errorf(`failed to set header: %w`, err)
	}
	if v := enc.KeyID(); v != "" {
		if err := r.Headers().Set(KeyIDKey, v); err != nil {
			return nil, nil, fmt.Errorf(`failed to set header: %w`, err)
		}
	}

	var rawCEK []byte
	enckey, err := enc.Encrypt(cek)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to encrypt key: %w`, err)
	}
	if enc.Algorithm() == jwa.ECDH_ES || enc.Algorithm() == jwa.DIRECT {
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

func Encrypt(payload []byte, options ...EncryptOption) ([]byte, error) {
	// default content encryption algorithm
	calg := jwa.A256GCM

	// default compression is "none"
	compression := jwa.NoCompress

	format := fmtCompact

	// builds each "recipient" with encrypted_key and headers
	var builders []*recipientBuilder

	var protected Headers
	var useRawCEK bool
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identKey{}:
			data := option.Value().(*withKey)
			v, ok := data.alg.(jwa.KeyEncryptionAlgorithm)
			if !ok {
				return nil, fmt.Errorf(`jwe.Encrypt: expected alg to be jwa.KeyEncryptionAlgorithm, but got %T`, data.alg)
			}

			switch v {
			case jwa.DIRECT, jwa.ECDH_ES:
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
		case identProtectedHeaders{}:
			protected = option.Value().(Headers)
		case identSerialization{}:
			format = option.Value().(int)
		}
	}

	// We need to have at least one builder
	if len(builders) == 0 {
		return nil, fmt.Errorf(`jwe.Encrypt: missing key encryption builders: use jwe.WithKey() to specify one`)
	}

	if useRawCEK {
		if len(builders) != 1 {
			return nil, fmt.Errorf(`jwe.Encrypt: multiple recipients for ECDH-ES/DIRECT mode supported`)
		}
	}

	// There is exactly one content encrypter.
	contentcrypt, err := content_crypt.NewGeneric(calg)
	if err != nil {
		return nil, fmt.Errorf(`jwe.Encrypt: failed to create AES encrypter: %w`, err)
	}

	generator := keygen.NewRandom(contentcrypt.KeySize())
	bk, err := generator.Generate()
	if err != nil {
		return nil, fmt.Errorf(`jwe.Encrypt: failed to generate key: %w`, err)
	}
	cek := bk.Bytes()

	recipients := make([]Recipient, len(builders))
	for i, builder := range builders {
		// some builders require hint from the contentcrypt object
		r, rawCEK, err := builder.Build(cek, calg, contentcrypt)
		if err != nil {
			return nil, fmt.Errorf(`jwe.Encrypt: failed to create recipient #%d: %w`, i, err)
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
		return nil, fmt.Errorf(`jwe.Encrypt: failed to set "enc" in protected header: %w`, err)
	}

	if compression != jwa.NoCompress {
		payload, err = compress(payload)
		if err != nil {
			return nil, fmt.Errorf(`jwe.Encrypt: failed to compress payload before encryption: %w`, err)
		}
		if err := protected.Set(CompressionKey, compression); err != nil {
			return nil, fmt.Errorf(`jwe.Encrypt: failed to set "zip" in protected header: %w`, err)
		}
	}

	// If there's only one recipient, you want to include that in the
	// protected header
	if len(recipients) == 1 {
		h, err := protected.Merge(context.TODO(), recipients[0].Headers())
		if err != nil {
			return nil, fmt.Errorf(`jwe.Encrypt: failed to merge protected headers: %w`, err)
		}
		protected = h
	}

	aad, err := protected.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64 encode protected headers")
	}

	iv, ciphertext, tag, err := contentcrypt.Encrypt(cek, payload, aad)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt payload")
	}

	msg := NewMessage()

	decodedAad, err := base64.Decode(aad)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64")
	}
	if err := msg.Set(AuthenticatedDataKey, decodedAad); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s`, AuthenticatedDataKey)
	}
	if err := msg.Set(CipherTextKey, ciphertext); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s`, CipherTextKey)
	}
	if err := msg.Set(InitializationVectorKey, iv); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s`, InitializationVectorKey)
	}
	if err := msg.Set(ProtectedHeadersKey, protected); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s`, ProtectedHeadersKey)
	}
	if err := msg.Set(RecipientsKey, recipients); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s`, RecipientsKey)
	}
	if err := msg.Set(TagKey, tag); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s`, TagKey)
	}

	switch format {
	case fmtCompact:
		return Compact(msg)
	case fmtJSON:
		return JSON(msg)
	default:
		return nil, fmt.Errorf(`jwe.Encrypt: invalid serialization`)
	}
}

// DecryptCtx is used internally when jwe.Decrypt is called, and is
// passed for hooks that you may pass into it.
//
// Regular users should not have to touch this object, but if you need advanced handling
// of messages, you might have to use it. Only use it when you really
// understand how JWE processing works in this library.
type DecryptCtx interface {
	Algorithm() jwa.KeyEncryptionAlgorithm
	SetAlgorithm(jwa.KeyEncryptionAlgorithm)
	Key() interface{}
	SetKey(interface{})
	Message() *Message
	SetMessage(*Message)
}

type decryptCtx struct {
	alg jwa.KeyEncryptionAlgorithm
	key interface{}
	msg *Message
}

func (ctx *decryptCtx) Algorithm() jwa.KeyEncryptionAlgorithm {
	return ctx.alg
}

func (ctx *decryptCtx) SetAlgorithm(v jwa.KeyEncryptionAlgorithm) {
	ctx.alg = v
}

func (ctx *decryptCtx) Key() interface{} {
	return ctx.key
}

func (ctx *decryptCtx) SetKey(v interface{}) {
	ctx.key = v
}

func (ctx *decryptCtx) Message() *Message {
	return ctx.msg
}

func (ctx *decryptCtx) SetMessage(m *Message) {
	ctx.msg = m
}

// Decrypt takes the key encryption algorithm and the corresponding
// key to decrypt the JWE message, and returns the decrypted payload.
// The JWE message can be either compact or full JSON format.
//
// `alg` accepts a `jwa.KeyAlgorithm` for convenience so you can directly pass
// the result of `(jwk.Key).Algorithm()`, but in practice it must be of type
// `jwa.KeyEncryptionAlgorithm` or otherwise it will cause an error.
//
// `key` must be a private key. It can be either in its raw format (e.g. *rsa.PrivateKey) or a jwk.Key
func Decrypt(buf []byte, alg jwa.KeyAlgorithm, key interface{}, options ...DecryptOption) ([]byte, error) {
	keyalg, ok := alg.(jwa.KeyEncryptionAlgorithm)
	if !ok {
		return nil, errors.Errorf(`expected alg to be jwa.KeyEncryptionAlgorithm, but got %T`, alg)
	}

	var ctx decryptCtx
	ctx.key = key
	ctx.alg = keyalg

	var dst *Message
	var postParse PostParser
	//nolint:forcetypeassert
	for _, option := range options {
		switch option.Ident() {
		case identMessage{}:
			dst = option.Value().(*Message)
		case identPostParser{}:
			postParse = option.Value().(PostParser)
		}
	}

	msg, err := parseJSONOrCompact(buf, true)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse buffer for Decrypt")
	}

	ctx.msg = msg
	if postParse != nil {
		if err := postParse.PostParse(&ctx); err != nil {
			return nil, errors.Wrap(err, `failed to execute PostParser hook`)
		}
	}

	payload, err := doDecryptCtx(&ctx)
	if err != nil {
		return nil, errors.Wrap(err, `failed to decrypt message`)
	}

	if dst != nil {
		*dst = *msg
		dst.rawProtectedHeaders = nil
		dst.storeProtectedHeaders = false
	}

	return payload, nil
}

// Parse parses the JWE message into a Message object. The JWE message
// can be either compact or full JSON format.
func Parse(buf []byte) (*Message, error) {
	return parseJSONOrCompact(buf, false)
}

func parseJSONOrCompact(buf []byte, storeProtectedHeaders bool) (*Message, error) {
	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return nil, errors.New("empty buffer")
	}

	if buf[0] == '{' {
		return parseJSON(buf, storeProtectedHeaders)
	}
	return parseCompact(buf, storeProtectedHeaders)
}

// ParseString is the same as Parse, but takes a string.
func ParseString(s string) (*Message, error) {
	return Parse([]byte(s))
}

// ParseReader is the same as Parse, but takes an io.Reader.
func ParseReader(src io.Reader) (*Message, error) {
	buf, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, errors.Wrap(err, `failed to read from io.Reader`)
	}
	return Parse(buf)
}

func parseJSON(buf []byte, storeProtectedHeaders bool) (*Message, error) {
	m := NewMessage()
	m.storeProtectedHeaders = storeProtectedHeaders
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, errors.Wrap(err, "failed to parse JSON")
	}
	return m, nil
}

func parseCompact(buf []byte, storeProtectedHeaders bool) (*Message, error) {
	parts := bytes.Split(buf, []byte{'.'})
	if len(parts) != 5 {
		return nil, errors.Errorf(`compact JWE format must have five parts (%d)`, len(parts))
	}

	hdrbuf, err := base64.Decode(parts[0])
	if err != nil {
		return nil, errors.Wrap(err, `failed to parse first part of compact form`)
	}

	protected := NewHeaders()
	if err := json.Unmarshal(hdrbuf, protected); err != nil {
		return nil, errors.Wrap(err, "failed to parse header JSON")
	}

	ivbuf, err := base64.Decode(parts[2])
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64 decode iv")
	}

	ctbuf, err := base64.Decode(parts[3])
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64 decode content")
	}

	tagbuf, err := base64.Decode(parts[4])
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64 decode tag")
	}

	m := NewMessage()
	if err := m.Set(CipherTextKey, ctbuf); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s`, CipherTextKey)
	}
	if err := m.Set(InitializationVectorKey, ivbuf); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s`, InitializationVectorKey)
	}
	if err := m.Set(ProtectedHeadersKey, protected); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s`, ProtectedHeadersKey)
	}

	if err := m.makeDummyRecipient(string(parts[1]), protected); err != nil {
		return nil, errors.Wrap(err, `failed to setup recipient`)
	}

	if err := m.Set(TagKey, tagbuf); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s`, TagKey)
	}

	if storeProtectedHeaders {
		// This is later used for decryption.
		m.rawProtectedHeaders = parts[0]
	}

	return m, nil
}

// RegisterCustomField allows users to specify that a private field
// be decoded as an instance of the specified type. This option has
// a global effect.
//
// For example, suppose you have a custom field `x-birthday`, which
// you want to represent as a string formatted in RFC3339 in JSON,
// but want it back as `time.Time`.
//
// In that case you would register a custom field as follows
//
//   jwe.RegisterCustomField(`x-birthday`, timeT)
//
// Then `hdr.Get("x-birthday")` will still return an `interface{}`,
// but you can convert its type to `time.Time`
//
//   bdayif, _ := hdr.Get(`x-birthday`)
//   bday := bdayif.(time.Time)
func RegisterCustomField(name string, object interface{}) {
	registry.Register(name, object)
}
