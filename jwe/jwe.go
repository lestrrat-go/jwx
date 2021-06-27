//go:generate go run internal/cmd/genheader/main.go

// Package jwe implements JWE as described in https://tools.ietf.org/html/rfc7516
package jwe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
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
	"github.com/lestrrat-go/pdebug/v3"
	"github.com/pkg/errors"
)

var registry = json.NewRegistry()

// Encrypt takes the plaintext payload and encrypts it in JWE compact format.
// `key` should be a public key, and it may be a raw key (e.g. rsa.PublicKey) or a jwk.Key
//
// Encrypt currently does not support multi-recipient messages.
func Encrypt(payload []byte, keyalg jwa.KeyEncryptionAlgorithm, key interface{}, contentalg jwa.ContentEncryptionAlgorithm, compressalg jwa.CompressionAlgorithm, options ...EncryptOption) ([]byte, error) {
	if pdebug.Enabled {
		g := pdebug.FuncMarker()
		defer g.End()
	}

	var protected Headers
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identProtectedHeader{}:
			protected = option.Value().(Headers)
		}
	}
	if protected == nil {
		protected = NewHeaders()
	}

	contentcrypt, err := content_crypt.NewGeneric(contentalg)
	if err != nil {
		return nil, errors.Wrap(err, `failed to create AES encrypter`)
	}

	if jwkKey, ok := key.(jwk.Key); ok {
		var raw interface{}
		if err := jwkKey.Raw(&raw); err != nil {
			return nil, errors.Wrapf(err, `failed to retrieve raw key out of %T`, key)
		}

		key = raw
	}

	var enc keyenc.Encrypter
	switch keyalg {
	case jwa.RSA1_5:
		var pubkey rsa.PublicKey
		if err := keyconv.RSAPublicKey(&pubkey, key); err != nil {
			return nil, errors.Wrapf(err, "failed to generate public key from key (%T)", key)
		}

		enc, err = keyenc.NewRSAPKCSEncrypt(keyalg, &pubkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create RSA PKCS encrypter")
		}
	case jwa.RSA_OAEP, jwa.RSA_OAEP_256:
		var pubkey rsa.PublicKey
		if err := keyconv.RSAPublicKey(&pubkey, key); err != nil {
			return nil, errors.Wrapf(err, "failed to generate public key from key (%T)", key)
		}

		enc, err = keyenc.NewRSAOAEPEncrypt(keyalg, &pubkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create RSA OAEP encrypter")
		}
	case jwa.A128KW, jwa.A192KW, jwa.A256KW,
		jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW,
		jwa.PBES2_HS256_A128KW, jwa.PBES2_HS384_A192KW, jwa.PBES2_HS512_A256KW:
		sharedkey, ok := key.([]byte)
		if !ok {
			return nil, errors.New("invalid key: []byte required")
		}
		switch keyalg {
		case jwa.A128KW, jwa.A192KW, jwa.A256KW:
			enc, err = keyenc.NewAES(keyalg, sharedkey)
		case jwa.PBES2_HS256_A128KW, jwa.PBES2_HS384_A192KW, jwa.PBES2_HS512_A256KW:
			enc, err = keyenc.NewPBES2Encrypt(keyalg, sharedkey)
		default:
			enc, err = keyenc.NewAESGCMEncrypt(keyalg, sharedkey)
		}
		if err != nil {
			return nil, errors.Wrap(err, "failed to create key wrap encrypter")
		}
		// NOTE: there was formerly a restriction, introduced
		// in PR #26, which disallowed certain key/content
		// algorithm combinations. This seemed bogus, and
		// interop with the jose tool demonstrates it.
	case jwa.ECDH_ES, jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
		var keysize int
		switch keyalg {
		case jwa.ECDH_ES:
			// https://tools.ietf.org/html/rfc7518#page-15
			// In Direct Key Agreement mode, the output of the Concat KDF MUST be a
			// key of the same length as that used by the "enc" algorithm.
			keysize = contentcrypt.KeySize()
		case jwa.ECDH_ES_A128KW:
			keysize = 16
		case jwa.ECDH_ES_A192KW:
			keysize = 24
		case jwa.ECDH_ES_A256KW:
			keysize = 32
		}

		switch key := key.(type) {
		case x25519.PublicKey:
			enc, err = keyenc.NewECDHESEncrypt(keyalg, contentalg, keysize, key)
		default:
			var pubkey ecdsa.PublicKey
			if err := keyconv.ECDSAPublicKey(&pubkey, key); err != nil {
				return nil, errors.Wrapf(err, "failed to generate public key from key (%T)", key)
			}
			enc, err = keyenc.NewECDHESEncrypt(keyalg, contentalg, keysize, &pubkey)
		}
		if err != nil {
			return nil, errors.Wrap(err, "failed to create ECDHS key wrap encrypter")
		}
	case jwa.DIRECT:
		sharedkey, ok := key.([]byte)
		if !ok {
			return nil, errors.New("invalid key: []byte required")
		}
		enc, _ = keyenc.NewNoop(keyalg, sharedkey)
	default:
		if pdebug.Enabled {
			pdebug.Printf("Encrypt: unknown key encryption algorithm: %s", keyalg)
		}
		return nil, errors.Errorf(`invalid key encryption algorithm (%s)`, keyalg)
	}

	keysize := contentcrypt.KeySize()
	if pdebug.Enabled {
		pdebug.Printf("Encrypt: keysize = %d", keysize)
	}
	encctx := getEncryptCtx()
	defer releaseEncryptCtx(encctx)

	encctx.protected = protected
	encctx.contentEncrypter = contentcrypt
	encctx.generator = keygen.NewRandom(keysize)
	encctx.keyEncrypters = []keyenc.Encrypter{enc}
	encctx.compress = compressalg
	msg, err := encctx.Encrypt(payload)
	if err != nil {
		if pdebug.Enabled {
			pdebug.Printf("Encrypt: failed to encrypt: %s", err)
		}
		return nil, errors.Wrap(err, "failed to encrypt payload")
	}

	return Compact(msg)
}

// Decrypt takes the key encryption algorithm and the corresponding
// key to decrypt the JWE message, and returns the decrypted payload.
// The JWE message can be either compact or full JSON format.
//
// `key` must be a private key. It can be either in its raw format (e.g. *rsa.PrivateKey) or a jwk.Key
func Decrypt(buf []byte, alg jwa.KeyEncryptionAlgorithm, key interface{}) ([]byte, error) {
	if jwkKey, ok := key.(jwk.Key); ok {
		var raw interface{}
		if err := jwkKey.Raw(&raw); err != nil {
			return nil, errors.Wrapf(err, `failed to retrieve raw key from %T`, key)
		}
		key = raw
	}

	msg, err := Parse(buf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse buffer for Decrypt")
	}

	return msg.Decrypt(alg, key)
}

// Parse parses the JWE message into a Message object. The JWE message
// can be either compact or full JSON format.
func Parse(buf []byte) (*Message, error) {
	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return nil, errors.New("empty buffer")
	}

	if buf[0] == '{' {
		return parseJSON(buf)
	}
	return parseCompact(buf)
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

func parseJSON(buf []byte) (*Message, error) {
	m := NewMessage()
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, errors.Wrap(err, "failed to parse JSON")
	}
	return m, nil
}

func parseCompact(buf []byte) (*Message, error) {
	if pdebug.Enabled {
		pdebug.Printf("Parse(Compact): buf = '%s'", buf)
	}
	parts := bytes.Split(buf, []byte{'.'})
	if len(parts) != 5 {
		return nil, errors.Errorf(`compact JWE format must have five parts (%d)`, len(parts))
	}

	hdrbuf, err := base64.Decode(parts[0])
	if err != nil {
		return nil, errors.Wrap(err, `failed to parse first part of compact form`)
	}
	if pdebug.Enabled {
		pdebug.Printf("hdrbuf = %s", hdrbuf)
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
//
// For elements of headers, *the order of definition matters* when
// verifying the encrypted content.
//
// Suppose we are expecting a JSON object `{"bar":1, "foo":2}`
// in the protected header. Because we need to compute the AAD value
// using these headers, they are usually normalized in alphabetical order.
//
// And since we need to compute back the AAD value after we have parsed the
// JWE message, your custom type MUST serialize back to the same field order.
//
// As an example, configuring this library to parse the above JSON object
// into the following struct will case `jwe.Decrypt` to fail:
//
//    type Thing struct {
//      Foo int `json:"foo"`
//      Bar int `json:"bar"`
//    }
//    jwe.RegisterCustomField(..., Thing{})
//
// This is because `Thing`'s JSON serialization will be rendered
// by taking each of the fields in the order that they appear in
// the struct definition, thereby creating a JSON that looks like
// `{"foo":..., "bar":...}`. Notice that the order of keys are
// different from the original JSON representation. The JSON keys
// must be sorted.
//
// Therefore it is the caller's responsibility to make sure that
// the either (1) the struct's fields are declared in alphabetical
// order, or (2) provide a `MarshalJSON()` method in the custom type
// such that the alphabetical order is guaranteed in resulting
// JSON objects.
func RegisterCustomField(name string, object interface{}) {
	registry.Register(name, object)
}
