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
	EphemeralPublicKey     *jwk.ECDSAPublicKey            `json:"epk,omitempty"`
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
	KeyEncrypt([]byte) (ByteSource, error)
	// Kid returns the key id for this KeyEncrypter. This exists so that
	// you can pass in a KeyEncrypter to MultiEncrypt, you can rest assured
	// that the generated key will have the proper key ID.
	Kid() string
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

// KeyWrapEncrypt encrypts content encryption keys using AES-CGM key wrap.
// Contrary to what the name implies, it also decrypt encrypted keys
type KeyWrapEncrypt struct {
	alg       jwa.KeyEncryptionAlgorithm
	sharedkey []byte
	KeyID       string
}

// EcdhesKeyWrapEncrypt encrypts content encryption keys using ECDH-ES.
type EcdhesKeyWrapEncrypt struct {
	algorithm jwa.KeyEncryptionAlgorithm
	generator KeyGenerator
	KeyID       string
}

// EcdhesKeyWrapDecrypt decrypts keys using ECDH-ES.
type EcdhesKeyWrapDecrypt struct {
	algorithm jwa.KeyEncryptionAlgorithm
	apu       []byte
	apv       []byte
	privkey   *ecdsa.PrivateKey
	pubkey    *ecdsa.PublicKey
}

// ByteKey is a generated key that only has the key's byte buffer
// as its instance data. If a ke needs to do more, such as providing
// values to be set in a JWE header, that key type wraps a ByteKey
type ByteKey []byte

// ByteWithECPrivateKey holds the EC-DSA private key that generated
// the key along witht he key itself. This is required to set the
// proper values in the JWE headers
type ByteWithECPrivateKey struct {
	ByteKey
	PrivateKey *ecdsa.PrivateKey
}

// HeaderPopulater is an interface for things that may modify the
// JWE header. e.g. ByteWithECPrivateKey
type HeaderPopulater interface {
	HeaderPopulate(*Header)
}

// KeyGenerator generates the raw content encryption keys
type KeyGenerator interface {
	KeySize() int
	KeyGenerate() (ByteSource, error)
}

// ContentCipher knows how to encrypt/decrypt the content given a content
// encryption key and other data
type ContentCipher interface {
	KeySize() int
	encrypt(cek, aad, plaintext []byte) ([]byte, []byte, []byte, error)
	decrypt(cek, iv, aad, ciphertext, tag []byte) ([]byte, error)
}

// GenericContentCrypt encrypts a message by applying all the necessary
// modifications to the keys and the contents
type GenericContentCrypt struct {
	alg     jwa.ContentEncryptionAlgorithm
	keysize int
	tagsize int
	cipher  ContentCipher
	cekgen  KeyGenerator
	ivgen   KeyGenerator
}

// StaticKeyGenerate uses a static byte buffer to provide keys.
type StaticKeyGenerate []byte

// RandomKeyGenerate generates random keys
type RandomKeyGenerate struct {
	keysize int
}

// EcdhesKeyGenerate generates keys using ECDH-ES algorithm
type EcdhesKeyGenerate struct {
	algorithm jwa.KeyEncryptionAlgorithm
	keysize   int
	pubkey    *ecdsa.PublicKey
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

// AeadFetcher is an interface for things that can fetch AEAD ciphers
type AeadFetcher interface {
	AeadFetch([]byte) (cipher.AEAD, error)
}

// AeadFetchFunc fetches a AEAD cipher from the given key, and is
// represented by a function
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

// RSAPKCS15KeyDecrypt decrypts keys using RSA PKCS1v15 algorithm
type RSAPKCS15KeyDecrypt struct {
	alg       jwa.KeyEncryptionAlgorithm
	privkey   *rsa.PrivateKey
	generator KeyGenerator
}

// RSAPKCSKeyEncrypt encrypts keys using RSA PKCS1v15 algorithm
type RSAPKCSKeyEncrypt struct {
	alg    jwa.KeyEncryptionAlgorithm
	pubkey *rsa.PublicKey
	KeyID    string
}

// RSAOAEPKeyEncrypt encrypts keys using RSA OAEP algorithm
type RSAOAEPKeyEncrypt struct {
	alg    jwa.KeyEncryptionAlgorithm
	pubkey *rsa.PublicKey
	KeyID    string
}

// RSAOAEPKeyDecrypt decrypts keys using RSA OAEP algorithm
type RSAOAEPKeyDecrypt struct {
	alg     jwa.KeyEncryptionAlgorithm
	privkey *rsa.PrivateKey
}

// DirectDecrypt does not encryption (Note: Unimplemented)
type DirectDecrypt struct {
	Key []byte
}


