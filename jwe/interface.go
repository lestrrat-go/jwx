package jwe

import (
	"errors"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
)

var (
	ErrInvalidCompactPartsCount = errors.New("compact JWE format must have five parts")
	ErrInvalidHeaderValue       = errors.New("invalid value for header key")
	ErrUnsupportedAlgorithm     = errors.New("unspported algorithm")
	ErrMissingPrivateKey        = errors.New("missing private key")
)

// Base64Encoder can encode itself into base64. But you can do more such as
// filling default values, validating them, etc. This is used in `Encode()`
// as both headers and payloads
type Base64Encoder interface {
	Base64Encode() ([]byte, error)
}

type Base64Decoder interface {
	Base64Decode([]byte) error
}

type EssentialHeader struct {
	Algorithm              jwa.KeyEncryptionAlgorithm     `json:"alg"`
	ContentEncryption      jwa.ContentEncryptionAlgorithm `json:"enc,omitempty"`
	ContentType            string                         `json:"cty,omitempty"`
	Compression            jwa.CompressionAlgorithm       `json:"zip,omitempty"`
	Critical               []string                       `json:"crit,omitempty"`
	Jwk                    jwk.JSONWebKey                 `json:"jwk,omitempty"` // public key
	JwkSetURL              *url.URL                       `json:"jku,omitempty"`
	KeyID                  string                         `json:"kid,omitempty"`
	Type                   string                         `json:"typ,omitempty"` // e.g. "JWT"
	X509Url                *url.URL                       `json:"x5u,omitempty"`
	X509CertChain          []string                       `json:"x5c,omitempty"`
	X509CertThumbprint     string                         `json:"x5t,omitempty"`
	X509CertThumbprintS256 string                         `json:"x5t#S256,omitempty"`
}

// Header represents a jws header.
type Header struct {
	*EssentialHeader `json:"-"`
	PrivateParams    map[string]interface{} `json:"-"`
}

// EncodedHeader represents a header value that is base64 encoded
// in JSON format
type EncodedHeader struct {
	Header
	encoded buffer.Buffer // sometimes our encoding and the source encoding don't match
}

type KeyEncrypter interface {
	Algorithm() jwa.KeyEncryptionAlgorithm
	Kid() string
	KeyEncrypt([]byte) ([]byte, error)
}

type Recipient struct {
	Header       Header        `json:"header"`
	EncryptedKey buffer.Buffer `json:"encrypted_key"`
}

type Message struct {
	CipherText           buffer.Buffer `json:"ciphertext"`
	ProtectedHeader      EncodedHeader `json:"protected"`
	InitializationVector buffer.Buffer `json:"iv,omitempty"`
	Tag                  buffer.Buffer `json:"tag,omitempty"`
	AuthenticatedData    buffer.Buffer `json:"aad,omitempty"`
	Recipients           []Recipient   `json:"recipients"`
	Unprotected          string        `json:"unprotected,omitempty"`
}

type MultiEncrypter interface {
	MultiEncrypt([]byte) (*Message, error)
}

type ContentEncrypter interface {
	Algorithm() jwa.ContentEncryptionAlgorithm
	Encrypt([]byte, []byte) ([]byte, []byte, []byte, []byte, error)
}

type MultiEncrypt struct {
	ContentEncrypter ContentEncrypter
	KeyGenerator     KeyGenerator
	KeyEncrypters    []KeyEncrypter
	// KeyGenerator creates the random CEK.
}

// In JWE, multiple recipients may exist -- they receive an encrypted version
// of the CEK, using their key encryption algorithm of choice. On the other hand,
// there's only one content cipher.

func (e MultiEncrypt) BuildMessage(plaintext, aad []byte) (*Message, error) {
	cek, err := e.KeyGenerator.KeyGenerate()
	if err != nil {
		return nil, err
	}

	recipients := make([]Recipient, len(e.KeyEncrypters))
	for i, enc := range e.KeyEncrypters {
		r := NewRecipient()
		r.Header.Set("alg", enc.Algorithm())
		if v := enc.Kid(); v != "" {
			r.Header.Set("kid", v)
		}
		enckey, err := enc.KeyEncrypt(cek)
		if err != nil {
			return nil, err
		}
		r.EncryptedKey = enckey
		recipients[i] = *r
	}

	_, iv, ciphertext, tag, err := e.ContentEncrypter.Encrypt(plaintext, aad)

	protected := EncodedHeader{Header: *NewHeader()}
	protected.ContentEncryption = e.ContentEncrypter.Algorithm()

	return &Message{
		AuthenticatedData:    aad,
		CipherText:           ciphertext,
		InitializationVector: iv,
		ProtectedHeader:      protected,
		Recipients:           recipients,
		Tag:                  tag,
		//		Unprotected: TODO
	}, nil
}
