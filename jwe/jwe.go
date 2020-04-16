//go:generate go run internal/cmd/genheader/main.go

// Package jwe implements JWE as described in https://tools.ietf.org/html/rfc7516
package jwe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"

	"github.com/lestrrat-go/jwx/buffer"
	"github.com/lestrrat-go/jwx/internal/debug"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/internal/content_crypt"
	"github.com/lestrrat-go/jwx/jwe/internal/keyenc"
	"github.com/lestrrat-go/jwx/jwe/internal/keygen"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

// Encrypt takes the plaintext payload and encrypts it in JWE compact format.
func Encrypt(payload []byte, keyalg jwa.KeyEncryptionAlgorithm, key interface{}, contentalg jwa.ContentEncryptionAlgorithm, compressalg jwa.CompressionAlgorithm) ([]byte, error) {
	contentcrypt, err := content_crypt.NewAES(contentalg)
	if err != nil {
		return nil, errors.Wrap(err, `failed to create AES encrypter`)
	}

	var enc keyenc.Encrypter
	var keysize int
	switch keyalg {
	case jwa.RSA1_5:
		pubkey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key: *rsa.PublicKey required")
		}
		enc, err = keyenc.NewRSAPKCSEncrypt(keyalg, pubkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create RSA PKCS encrypter")
		}
		keysize = contentcrypt.KeySize() / 2
	case jwa.RSA_OAEP, jwa.RSA_OAEP_256:
		pubkey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key: *rsa.PublicKey required")
		}
		enc, err = keyenc.NewRSAOAEPEncrypt(keyalg, pubkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create RSA OAEP encrypter")
		}
		keysize = contentcrypt.KeySize() / 2
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		sharedkey, ok := key.([]byte)
		if !ok {
			return nil, errors.New("invalid key: []byte required")
		}
		enc, err = keyenc.NewAESCGM(keyalg, sharedkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create key wrap encrypter")
		}
		keysize = contentcrypt.KeySize()
		switch aesKeySize := keysize / 2; aesKeySize {
		case 16, 24, 32:
		default:
			return nil, errors.Errorf("unsupported keysize %d (from content encryption algorithm %s). consider using content encryption that uses 32, 48, or 64 byte keys", keysize, contentalg)
		}
	case jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
		pubkey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key: *ecdsa.PublicKey required")
		}
		enc, err = keyenc.NewECDHESEncrypt(keyalg, pubkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create ECDHS key wrap encrypter")
		}
		keysize = contentcrypt.KeySize() / 2
	case jwa.ECDH_ES:
		fallthrough
	case jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW:
		fallthrough
	case jwa.PBES2_HS256_A128KW, jwa.PBES2_HS384_A192KW, jwa.PBES2_HS512_A256KW:
		fallthrough
	default:
		if debug.Enabled {
			debug.Printf("Encrypt: unknown key encryption algorithm: %s", keyalg)
		}
		return nil, errors.Wrap(ErrUnsupportedAlgorithm, "failed to create encrypter")
	}

	if debug.Enabled {
		debug.Printf("Encrypt: keysize = %d", keysize)
	}
	encctx := getEncryptCtx()
	encctx.contentEncrypter = contentcrypt
	encctx.generator = keygen.NewRandom(keysize)
	encctx.keyEncrypters = []keyenc.Encrypter{enc}
	msg, err := encctx.Encrypt(payload)
	if err != nil {
		if debug.Enabled {
			debug.Printf("Encrypt: failed to encrypt: %s", err)
		}
		return nil, errors.Wrap(err, "failed to encrypt payload")
	}

	return Compact(msg)
}

// Decrypt takes the key encryption algorithm and the corresponding
// key to decrypt the JWE message, and returns the decrypted payload.
// The JWE message can be either compact or full JSON format.
func Decrypt(buf []byte, alg jwa.KeyEncryptionAlgorithm, key interface{}) ([]byte, error) {
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

func parseJSON(buf []byte) (*Message, error) {
	m := struct {
		*Message
		*Recipient
	}{}

	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, errors.Wrap(err, "failed to parse JSON")
	}

	// if the "signature" field exist, treat it as a flattened
	if m.Recipient != nil {
		if len(m.Message.recipients) != 0 {
			return nil, errors.New("invalid message: mixed flattened/full json serialization")
		}

		m.Message.recipients = []Recipient{*m.Recipient}
	}

	return m.Message, nil
}

func parseCompact(buf []byte) (*Message, error) {
	if debug.Enabled {
		debug.Printf("Parse(Compact): buf = '%s'", buf)
	}
	parts := bytes.Split(buf, []byte{'.'})
	if len(parts) != 5 {
		return nil, ErrInvalidCompactPartsCount
	}

	hdrbuf := buffer.Buffer{}
	if err := hdrbuf.Base64Decode(parts[0]); err != nil {
		return nil, errors.Wrap(err, `failed to parse first part of compact form`)
	}
	if debug.Enabled {
		debug.Printf("hdrbuf = %s", hdrbuf)
	}

	hdr := NewHeaders()
	if err := json.Unmarshal(hdrbuf, hdr); err != nil {
		return nil, errors.Wrap(err, "failed to parse header JSON")
	}

	// We need the protected header to contain the content encryption
	// algorithm. XXX probably other headers need to go there too
	protected := NewHeaders()
	protected.Set(ContentEncryptionKey, hdr.ContentEncryption())
	hdr.Set(ContentEncryptionKey, "")

	var enckeybuf buffer.Buffer
	if err := enckeybuf.Base64Decode(parts[1]); err != nil {
		return nil, errors.Wrap(err, "failed to base64 decode encryption key")
	}

	var ivbuf buffer.Buffer
	if err := ivbuf.Base64Decode(parts[2]); err != nil {
		return nil, errors.Wrap(err, "failed to base64 decode iv")
	}

	var ctbuf buffer.Buffer
	if err := ctbuf.Base64Decode(parts[3]); err != nil {
		return nil, errors.Wrap(err, "failed to base64 decode content")
	}

	var tagbuf buffer.Buffer
	if err := tagbuf.Base64Decode(parts[4]); err != nil {
		return nil, errors.Wrap(err, "failed to base64 decode tag")
	}

	m := NewMessage()
	m.authenticatedData.SetBytes(hdrbuf.Bytes())
	m.protectedHeaders = protected
	m.tag = tagbuf
	m.cipherText = ctbuf
	m.initializationVector = ivbuf
	m.recipients = []Recipient{
		{
			Headers:      hdr,
			EncryptedKey: enckeybuf,
		},
	}
	return m, nil
}

// BuildKeyDecrypter creates a new KeyDecrypter instance from the given
// parameters. It is used by the Message.Decrypt method to create
// key decrypter(s) from the given message. `keysize` is only used by
// some decrypters. Pass the value from ContentCipher.KeySize().
func BuildKeyDecrypter(alg jwa.KeyEncryptionAlgorithm, h Headers, key interface{}, keysize int) (keyenc.Decrypter, error) {
	switch alg {
	case jwa.RSA1_5:
		privkey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.Errorf("*rsa.PrivateKey is required as the key to build %s key decrypter", alg)
		}
		return keyenc.NewRSAPKCS15Decrypt(alg, privkey, keysize/2), nil
	case jwa.RSA_OAEP, jwa.RSA_OAEP_256:
		privkey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.Errorf("*rsa.PrivateKey is required as the key to build %s key decrypter", alg)
		}
		return keyenc.NewRSAOAEPDecrypt(alg, privkey)
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		sharedkey, ok := key.([]byte)
		if !ok {
			return nil, errors.Errorf("[]byte is required as the key to build %s key decrypter", alg)
		}
		return keyenc.NewAESCGM(alg, sharedkey)
	case jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
		epkif, ok := h.Get(EphemeralPublicKeyKey)
		if !ok {
			return nil, errors.New("failed to get 'epk' field")
		}
		if epkif == nil {
			return nil, errors.Errorf("'epk' header is required as the key to build %s key decrypter", alg)
		}

		epk, ok := epkif.(*jwk.ECDSAPublicKey)
		if !ok {
			return nil, errors.Errorf("'epk' header is required as the key to build %s key decrypter", alg)
		}

		pubkey, err := epk.Materialize()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get public key")
		}

		privkey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.Errorf("*ecdsa.PrivateKey is required as the key to build %s key decrypter", alg)
		}
		var apuData, apvData []byte
		apu := h.AgreementPartyUInfo()
		if apu.Len() > 0 {
			apuData = apu.Bytes()
		}

		apv := h.AgreementPartyVInfo()
		if apv.Len() > 0 {
			apuData = apu.Bytes()
		}

		return keyenc.NewECDHESDecrypt(alg, pubkey.(*ecdsa.PublicKey), apuData, apvData, privkey), nil
	}

	return nil, NewErrUnsupportedAlgorithm(string(alg), "key decryption")
}
