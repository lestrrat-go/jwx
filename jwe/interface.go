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

// Message contains the entire encrypted JWE message. You should not
// expect to use Message for anything other than inspecting the
// state of an encrypted message. This is because encryption is
// highly context sensitive, and once we parse the original payload
// into an object, we may not always be able to recreate the exact
// context in which the encryption happened.
//
// For example, it is totally valid for if the protected header's
// integrity was calculated using a non-standard line breaks:
//
//    {"a dummy":
//      "protected header"}
//
// Once parsed, though, we can only serialize the protected header as:
//
//    {"a dummy":"protected header"}
//
// which would obviously result in a contradicting integrity value
// if we tried to re-calculate it from a parsed message.
//nolint:govet
type Message struct {
	authenticatedData    []byte
	cipherText           []byte
	initializationVector []byte
	tag                  []byte
	recipients           []Recipient
	protectedHeaders     Headers
	unprotectedHeaders   Headers
}

// contentEncrypter encrypts the content using the content using the
// encrypted key
type contentEncrypter interface {
	Algorithm() jwa.ContentEncryptionAlgorithm
	Encrypt([]byte, []byte, []byte) ([]byte, []byte, []byte, error)
}

//nolint:govet
type encryptCtx struct {
	keyEncrypters    []keyenc.Encrypter
	protected        Headers
	contentEncrypter contentEncrypter
	generator        keygen.Generator
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
