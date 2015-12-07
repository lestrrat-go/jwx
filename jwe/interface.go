package jwe

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
)

// Errors used in JWE
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

// NewErrUnsupportedAlgorithm creates a new UnsupportedAlgorithm error
func NewErrUnsupportedAlgorithm(alg, purpose string) errUnsupportedAlgorithm {
	return errUnsupportedAlgorithm{alg: alg, purpose: purpose}
}

// Error returns the string representation of the error
func (e errUnsupportedAlgorithm) Error() string {
	return fmt.Sprintf("unsupported algorithm '%s' for %s", e.alg, e.purpose)
}

// EssentialHeader is a set of headers that are already defined in RFC 7516`
type EssentialHeader struct {
	AgreementPartyUInfo    buffer.Buffer                  `json:"apu,omitempty"`
	AgreementPartyVInfo    buffer.Buffer                  `json:"apv,omitempty"`
	Algorithm              jwa.KeyEncryptionAlgorithm     `json:"alg,omitempty"`
	ContentEncryption      jwa.ContentEncryptionAlgorithm `json:"enc,omitempty"`
	ContentType            string                         `json:"cty,omitempty"`
	Compression            jwa.CompressionAlgorithm       `json:"zip,omitempty"`
	Critical               []string                       `json:"crit,omitempty"`
	EphemeralPublicKey     *jwk.EcdsaPublicKey            `json:"epk,omitempty"`
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

// ByteSource is an interface for things that return a byte sequence.
// This is used for KeyGenerator so that the result of computations can
// carry more than just the generate byte sequence.
type ByteSource interface {
	Bytes() []byte
}

// KeyEncrypter is an interface for things that can encrypt keys
type KeyEncrypter interface {
	Algorithm() jwa.KeyEncryptionAlgorithm
	Kid() string
	KeyEncrypt([]byte) (ByteSource, error)
}

// KeyDecrypter is an interface for things that can decrypt keys
type KeyDecrypter interface {
	Algorithm() jwa.KeyEncryptionAlgorithm
	KeyDecrypt([]byte) ([]byte, error)
}

// Recipient holds the encrypted key and hints to decrypt the key
type Recipient struct {
	Header       *Header       `json:"header"`
	EncryptedKey buffer.Buffer `json:"encrypted_key"`
}

// Message contains the entire encrypted JWE message
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

// ContentEncrypter encrypts the content using the content using the
// encrypted key
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

type KeyWrapEncrypt struct {
	alg       jwa.KeyEncryptionAlgorithm
	KeyID     string
	sharedkey []byte
}

type EcdhesKeyWrapEncrypt struct {
	algorithm jwa.KeyEncryptionAlgorithm
	generator KeyGenerator
	KeyID     string
}

type EcdhesKeyWrapDecrypt struct {
	algorithm jwa.KeyEncryptionAlgorithm
	apu       []byte
	apv       []byte
	privkey   *ecdsa.PrivateKey
	pubkey    *ecdsa.PublicKey
}

type KeyDecoder interface {
	KeyDecode([]byte) ([]byte, error)
}

type RsaOaepKeyDecode struct {
	Algorithm  jwa.KeyEncryptionAlgorithm
	PrivateKey *rsa.PrivateKey
}

type ByteKey []byte
type ByteWithECPrivateKey struct {
	ByteKey
	PrivateKey *ecdsa.PrivateKey
}

type HeaderPopulater interface {
	HeaderPopulate(*Header)
}

type KeyGenerator interface {
	KeySize() int
	KeyGenerate() (ByteSource, error)
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

type EcdhesKeyGenerate struct {
	algorithm jwa.KeyEncryptionAlgorithm
	keysize   int
	pubkey    *ecdsa.PublicKey
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

// AesContentCipher represents a cipher based on AES
type AesContentCipher struct {
	AeadFetcher
	NonceGenerator KeyGenerator
	keysize        int
	tagsize        int
}

// RsaContentCipher represents a cipher based on RSA
type RsaContentCipher struct {
	pubkey *rsa.PublicKey
}

// RSAPKCS15KeyEncrypt encrypts keys using RSA OAEP algorithm
type RSAPKCS15KeyDecrypt struct {
	alg       jwa.KeyEncryptionAlgorithm
	privkey   *rsa.PrivateKey
	generator KeyGenerator
}

// RSAOAEPKeyEncrypt encrypts keys using RSA OAEP algorithm
type RSAOAEPKeyEncrypt struct {
	alg    jwa.KeyEncryptionAlgorithm
	pubkey *rsa.PublicKey
	KeyID  string
}

// RSAPKCSKeyEncrypt encrypts keys using RSA PKCS algorithm
type RSAPKCSKeyEncrypt struct {
	alg    jwa.KeyEncryptionAlgorithm
	pubkey *rsa.PublicKey
	KeyID  string
}
