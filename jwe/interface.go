package jwe

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/buffer"
	"github.com/lestrrat-go/jwx/internal/iter"
	"github.com/lestrrat-go/jwx/internal/option"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/internal/keyenc"
	"github.com/lestrrat-go/jwx/jwe/internal/keygen"
)

const (
	optkeyPrettyJSONFormat = "optkeyPrettyJSONFormat"
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
	encrypters       []keyenc.Encrypter
}

// populater is an interface for things that may modify the
// JWE header. e.g. ByteWithECPrivateKey
type populater interface {
	Populate(keygen.Setter)
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

type Visitor = iter.MapVisitor
type VisitorFunc = iter.MapVisitorFunc
type HeaderPair = mapiter.Pair
type Iterator = mapiter.Iterator
type Option = option.Interface
