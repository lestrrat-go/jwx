package jws

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
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
	Algorithm              jwa.SignatureAlgorithm `json:"alg,omitempty"`
	ContentType            string                 `json:"cty,omitempty"`
	Critical               []string               `json:"crit,omitempty"`
	Jwk                    jwk.JsonWebKey         `json:"jwk,omitempty"` // public key
	JwkSetUrl              *url.URL               `json:"jku,omitempty"`
	KeyId                  string                 `json:"kid,omitempty"`
	Type                   string                 `json:"typ,omitempty"` // e.g. "JWT"
	X509Url                *url.URL               `json:"x5u,omitempty"`
	X509CertChain          []string               `json:"x5c,omitempty"`
	X509CertThumbprint     string                 `json:"x5t,omitempty"`
	X509CertThumbprintS256 string                 `json:"x5t#S256,omitempty"`
}

// Header represents a jws header.
type Header struct {
	*EssentialHeader `json:"-"`
	PrivateParams    map[string]interface{} `json:"-"`
}

var ErrInvalidCompactPartsCount = errors.New("compact JWS format must have three parts")
var ErrUnsupportedAlgorithm = errors.New("unspported algorithm")

// Signer generates signature for the given payload
type Signer interface {
	Jwk() jwk.JsonWebKey
	Kid() string
	Alg() jwa.SignatureAlgorithm
	Sign([]byte) ([]byte, error)
}

// Verifier is used to verify the signature against the payload
type Verifier interface {
	Verify([]byte, []byte) error
}

type RsaSign struct {
	Algorithm  jwa.SignatureAlgorithm
	JsonWebKey *jwk.RsaPublicKey
	KeyId      string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type EcdsaSign struct {
	Algorithm  jwa.SignatureAlgorithm
	JsonWebKey *jwk.RsaPublicKey
	KeyId      string
	PrivateKey *ecdsa.PrivateKey
}

type Signature struct {
	Header    Header        `json:"header"`              // Raw JWS Unprotected Heders
	Protected buffer.Buffer `json:"protected,omitempty"` // Base64 encoded JWS Protected Headers
	Signature buffer.Buffer `json:"signature"`           // Base64 encoded signature
}

// Message represents a full JWS encoded message. Flattened serialization
// is not supported as a struct, but rather it's represented as a
// Message struct with only one `signature` element
type Message struct {
	Payload    buffer.Buffer `json:"payload"`
	Signatures []Signature   `json:"signatures"`
}

type MultiSigner interface {
	MultiSign(buffer.Buffer) (*Message, error)
	AddSigner(Signer)
}

type MultiSign struct {
	Signers []Signer
}
