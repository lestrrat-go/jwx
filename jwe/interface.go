package jwe

import (
	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/internal/iter"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/internal/keyenc"
	"github.com/lestrrat-go/jwx/jwe/internal/keygen"
)

// Recipient holds the encrypted key and hints to decrypt the key
type Recipient interface {
	Headers() Headers
	EncryptedKey() []byte
	SetHeaders(Headers) error
	SetEncryptedKey([]byte) error
}

type stdRecipient struct {
	headers      Headers
	encryptedKey []byte
}

// Message contains the entire encrypted JWE message
type Message struct {
	authenticatedData    []byte
	cipherText           []byte
	initializationVector []byte
	protectedHeaders     Headers
	recipients           []Recipient
	tag                  []byte
	unprotectedHeaders   Headers
}

// contentEncrypter encrypts the content using the content using the
// encrypted key
type contentEncrypter interface {
	Algorithm() jwa.ContentEncryptionAlgorithm
	Encrypt([]byte, []byte, []byte) ([]byte, []byte, []byte, error)
}

type encryptCtx struct {
	contentEncrypter contentEncrypter
	generator        keygen.Generator
	keyEncrypters    []keyenc.Encrypter
	compress         jwa.CompressionAlgorithm
}

// populater is an interface for things that may modify the
// JWE header. e.g. ByteWithECPrivateKey
type populater interface {
	Populate(keygen.Setter) error
}

type Visitor = iter.MapVisitor
type VisitorFunc = iter.MapVisitorFunc
type HeaderPair = mapiter.Pair
type Iterator = mapiter.Iterator
