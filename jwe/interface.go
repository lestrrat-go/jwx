package jwe

import (
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
}

// populater is an interface for things that may modify the
// JWE header. e.g. ByteWithECPrivateKey
type populater interface {
	Populate(keygen.Setter)
}

type Visitor = iter.MapVisitor
type VisitorFunc = iter.MapVisitorFunc
type HeaderPair = mapiter.Pair
type Iterator = mapiter.Iterator
type Option = option.Interface
