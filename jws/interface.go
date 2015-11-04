package jws

import (
	"crypto/rsa"
	"errors"

	"github.com/lestrrat/go-jwx/buffer"
)

// Signature algorithms
type SignatureAlgorithm string

const (
	HS256 SignatureAlgorithm = "HS256" // HMAC using SHA-256
	HS384                    = "HS384" // HMAC using SHA-384
	HS512                    = "HS512" // HMAC using SHA-512
	RS256                    = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384                    = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512                    = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	ES256                    = "ES256" // ECDSA using P-256 and SHA-256
	ES384                    = "ES384" // ECDSA using P-384 and SHA-384
	ES512                    = "ES512" // ECDSA using P-521 and SHA-512
	PS256                    = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384                    = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512                    = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
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

// Header is a very basic jws header. You may need to do use your own
// header or structs from other libraries in order to achieve some
// advanced functionalities. For this `jwx` library intentially only
// accepts interfaces into functions such as `Encode` so you can
// use your struct of choice
type Header struct {
	Algorithm string `json:"alg,omitempty"`
	KeyID     string `json:"kid,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Type      string `json:"typ,omitempty"` // e.g. "JWT"
}

type Compact struct {
	Header    buffer.Buffer
	Payload   buffer.Buffer
	Signature []byte
}

var ErrInvalidCompactPartsCount = errors.New("compact JWS format must have three parts")
var ErrUnsupportedAlgorithm = errors.New("unspported algorithm")

type Signer interface {
	Sign([]byte) ([]byte, error)
}

type Verifier interface {
	Verify([]byte) error
}

type RSASign struct {
	Algorithm  SignatureAlgorithm
	PrivateKey *rsa.PrivateKey
}
