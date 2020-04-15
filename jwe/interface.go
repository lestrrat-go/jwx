package jwe

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/buffer"
	"github.com/lestrrat-go/jwx/internal/iter"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/internal/cipher"
	"github.com/lestrrat-go/jwx/jwe/internal/keygen"
)

// Errors used in JWE
var (
	ErrInvalidBlockSize         = errors.New("keywrap input must be 8 byte blocks")
	ErrInvalidCompactPartsCount = errors.New("compact JWE format must have five parts")
	ErrInvalidHeaderValue       = errors.New("invalid value for header key")
	ErrUnsupportedAlgorithm     = errors.New("unsupported algorithm")
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

// KeyEncrypter is an interface for things that can encrypt keys
type KeyEncrypter interface {
	Algorithm() jwa.KeyEncryptionAlgorithm
	KeyEncrypt([]byte) (keygen.ByteSource, error)
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
	Headers      Headers       `json:"header"`
	EncryptedKey buffer.Buffer `json:"encrypted_key"`
}

// Message contains the entire encrypted JWE message
type Message struct {
	authenticatedData    buffer.Buffer `json:"aad,omitempty"`
	cipherText           buffer.Buffer `json:"ciphertext"`
	initializationVector buffer.Buffer `json:"iv,omitempty"`
	protectedHeaders     Headers       `json:"protected"`
	recipients           []Recipient   `json:"recipients"`
	tag                  buffer.Buffer `json:"tag,omitempty"`
	unprotectedHeaders   Headers       `json:"unprotected,omitempty"`
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
	generator        keygen.Generator
	KeyEncrypters    []KeyEncrypter
}

// KeyWrapEncrypt encrypts content encryption keys using AES-CGM key wrap.
// Contrary to what the name implies, it also decrypt encrypted keys
type KeyWrapEncrypt struct {
	alg       jwa.KeyEncryptionAlgorithm
	sharedkey []byte
	KeyID     string
}

// EcdhesKeyWrapEncrypt encrypts content encryption keys using ECDH-ES.
type EcdhesKeyWrapEncrypt struct {
	algorithm jwa.KeyEncryptionAlgorithm
	generator keygen.Generator
	KeyID     string
}

// EcdhesKeyWrapDecrypt decrypts keys using ECDH-ES.
type EcdhesKeyWrapDecrypt struct {
	algorithm jwa.KeyEncryptionAlgorithm
	apu       []byte
	apv       []byte
	privkey   *ecdsa.PrivateKey
	pubkey    *ecdsa.PublicKey
}

// populater is an interface for things that may modify the
// JWE header. e.g. ByteWithECPrivateKey
type populater interface {
	Populate(keygen.Setter)
}

// GenericContentCrypt encrypts a message by applying all the necessary
// modifications to the keys and the contents
type GenericContentCrypt struct {
	alg     jwa.ContentEncryptionAlgorithm
	keysize int
	tagsize int
	cipher  cipher.ContentCipher
	cekgen  keygen.Generator
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

// RSAPKCS15KeyDecrypt decrypts keys using RSA PKCS1v15 algorithm
type RSAPKCS15KeyDecrypt struct {
	alg       jwa.KeyEncryptionAlgorithm
	privkey   *rsa.PrivateKey
	generator keygen.Generator
}

// RSAPKCSKeyEncrypt encrypts keys using RSA PKCS1v15 algorithm
type RSAPKCSKeyEncrypt struct {
	alg    jwa.KeyEncryptionAlgorithm
	pubkey *rsa.PublicKey
	KeyID  string
}

// RSAOAEPKeyEncrypt encrypts keys using RSA OAEP algorithm
type RSAOAEPKeyEncrypt struct {
	alg    jwa.KeyEncryptionAlgorithm
	pubkey *rsa.PublicKey
	KeyID  string
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

type Visitor = iter.MapVisitor
type VisitorFunc = iter.MapVisitorFunc
type HeaderPair = mapiter.Pair
type Iterator = mapiter.Iterator
