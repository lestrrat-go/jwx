package jwe

import (
	"crypto/cipher"
	"crypto/rsa"
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
	*Header
	encoded buffer.Buffer // sometimes our encoding and the source encoding don't match
}

type KeyEncrypter interface {
	Algorithm() jwa.KeyEncryptionAlgorithm
	Kid() string
	KeyEncrypt([]byte) ([]byte, error)
}

type Recipient struct {
	Header       *Header       `json:"header"`
	EncryptedKey buffer.Buffer `json:"encrypted_key"`
}

type Message struct {
	CipherText           buffer.Buffer  `json:"ciphertext"`
	ProtectedHeader      *EncodedHeader `json:"protected"`
	InitializationVector buffer.Buffer  `json:"iv,omitempty"`
	Tag                  buffer.Buffer  `json:"tag,omitempty"`
	AuthenticatedData    buffer.Buffer  `json:"aad,omitempty"`
	Recipients           []Recipient    `json:"recipients"`
	Unprotected          string         `json:"unprotected,omitempty"`
}

// Encrypter is the top level structure that encrypts the given
// payload to a JWE message
type Encrypter interface {
	Encrypt([]byte) (*Message, error)
}

type ContentEncrypter interface {
	Algorithm() jwa.ContentEncryptionAlgorithm
	Encrypt([]byte, []byte) ([]byte, []byte, []byte, []byte, error)
}

// Encrypt is the default Encrypter implementation.
type Encrypt struct {
	ContentEncrypter ContentEncrypter
	KeyGenerator     KeyGenerator // KeyGenerator creates the random CEK.
	KeyEncrypters    []KeyEncrypter
}

// TODO GCM family
type KeyWrapEncrypt struct {
	alg       jwa.KeyEncryptionAlgorithm
	KeyID     string
	sharedkey []byte
}

type KeyDecoder interface {
	KeyDecode([]byte) ([]byte, error)
}

type RsaOaepKeyDecode struct {
	Algorithm  jwa.KeyEncryptionAlgorithm
	PrivateKey *rsa.PrivateKey
}

type KeyGenerator interface {
	KeySize() int
	KeyGenerate() ([]byte, error)
}

type ContentCipher interface {
	KeySize() int
	encrypt(cek, iv, aad, plaintext []byte) ([]byte, []byte, error)
	decrypt(cek, iv, aad, ciphertext, tag []byte) ([]byte, error)
}

type GenericContentCrypt struct {
	alg     jwa.ContentEncryptionAlgorithm
	keysize int
	tagsize int
	cipher  ContentCipher
	cekgen  KeyGenerator
	ivgen   KeyGenerator
}

type StaticKeyGenerate []byte

type RandomKeyGenerate struct {
	keysize int
}

// Serializer converts an encrypted message into a byte buffer
type Serializer interface {
	Serialize(*Message) ([]byte, error)
}

// CompactSerialize serializes the message into JWE compact serialized format
type CompactSerialize struct{}

// JSONSerialize serializes the message into JWE JSON serialized format. If you
// set `Pretty` to true, `json.MarshalIndent` is used instead of `json.Marshal`
type JSONSerialize struct {
	Pretty bool
}

type AeadFetcher interface {
	AeadFetch([]byte) (cipher.AEAD, error)
}

type AeadFetchFunc func([]byte) (cipher.AEAD, error)

type AesContentCipher struct {
	AeadFetcher
	sharedkey []byte
	keysize   int
	tagsize   int
}

type RsaContentCipher struct {
	pubkey *rsa.PublicKey
}
