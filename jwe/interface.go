package jwe

import (
	"crypto/cipher"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
)

var (
	ErrInvalidBlockSize         = errors.New("keywrap input must be 8 byte blocks")
	ErrInvalidCompactPartsCount = errors.New("compact JWE format must have five parts")
	ErrInvalidHeaderValue       = errors.New("invalid value for header key")
	ErrUnsupportedAlgorithm     = errors.New("unspported algorithm")
	ErrMissingPrivateKey        = errors.New("missing private key")
)

type errUnsupportedAlgorithm struct {
	alg     string
	purpose string
}

func NewErrUnsupportedAlgorithm(alg, purpose string) errUnsupportedAlgorithm {
	return errUnsupportedAlgorithm{alg: alg, purpose: purpose}
}

func (e errUnsupportedAlgorithm) Error() string {
	return fmt.Sprintf("unsupported algorithm '%s' for %s", e.alg, e.purpose)
}

type EssentialHeader struct {
	Algorithm              jwa.KeyEncryptionAlgorithm     `json:"alg,omitempty"`
	ContentEncryption      jwa.ContentEncryptionAlgorithm `json:"enc,omitempty"`
	ContentType            string                         `json:"cty,omitempty"`
	Compression            jwa.CompressionAlgorithm       `json:"zip,omitempty"`
	Critical               []string                       `json:"crit,omitempty"`
	Jwk                    jwk.Key                        `json:"jwk,omitempty"` // public key
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

type KeyDecrypter interface {
	Algorithm() jwa.KeyEncryptionAlgorithm
	KeyDecrypt([]byte) ([]byte, error)
}

type Recipient struct {
	Header       *Header       `json:"header"`
	EncryptedKey buffer.Buffer `json:"encrypted_key"`
}

type Message struct {
	AuthenticatedData    buffer.Buffer  `json:"aad,omitempty"`
	CipherText           buffer.Buffer  `json:"ciphertext"`
	InitializationVector buffer.Buffer  `json:"iv,omitempty"`
	ProtectedHeader      *EncodedHeader `json:"protected"`
	Recipients           []Recipient    `json:"recipients"`
	Tag                  buffer.Buffer  `json:"tag,omitempty"`
	UnprotectedHeader    *Header        `json:"unprotected,omitempty"`
}

// Encrypter is the top level structure that encrypts the given
// payload to a JWE message
type Encrypter interface {
	Encrypt([]byte) (*Message, error)
}

type ContentEncrypter interface {
	Algorithm() jwa.ContentEncryptionAlgorithm
	Encrypt([]byte, []byte, []byte) ([]byte, []byte, []byte, error)
}

// MultiEncrypt is the default Encrypter implementation.
type MultiEncrypt struct {
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
	encrypt(cek, aad, plaintext []byte) ([]byte, []byte, []byte, error)
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

type DynamicKeyGenerate struct{}

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
	NonceGenerator KeyGenerator
	keysize        int
	tagsize        int
}

type RsaContentCipher struct {
	pubkey *rsa.PublicKey
}

type RSAPKCS15KeyDecrypt struct {
	alg       jwa.KeyEncryptionAlgorithm
	privkey   *rsa.PrivateKey
	generator KeyGenerator
}

type RSAOAEPKeyEncrypt struct {
	alg    jwa.KeyEncryptionAlgorithm
	pubkey *rsa.PublicKey
	KeyID  string
}

type RSAPKCSKeyEncrypt struct {
	alg    jwa.KeyEncryptionAlgorithm
	pubkey *rsa.PublicKey
	KeyID  string
}

