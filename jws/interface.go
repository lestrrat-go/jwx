package jws

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwk"
)

// Signature algorithms
type SignatureAlgorithm string

const (
	NoSignature SignatureAlgorithm = "none"
	HS256                          = "HS256" // HMAC using SHA-256
	HS384                          = "HS384" // HMAC using SHA-384
	HS512                          = "HS512" // HMAC using SHA-512
	RS256                          = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384                          = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512                          = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	ES256                          = "ES256" // ECDSA using P-256 and SHA-256
	ES384                          = "ES384" // ECDSA using P-384 and SHA-384
	ES512                          = "ES512" // ECDSA using P-521 and SHA-512
	PS256                          = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384                          = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512                          = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
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
	Algorithm              SignatureAlgorithm `json:"alg,omitempty"`
	ContentType            string             `json:"cty,omitempty"`
	Critical               []string           `json:"crit,omitempty"`
	Jwk                    jwk.JsonWebKey     `json:"jwk,omitempty"` // public key
	JwkSetUrl              *url.URL           `json:"jku,omitempty"`
	KeyId                  string             `json:"kid,omitempty"`
	Type                   string             `json:"typ,omitempty"` // e.g. "JWT"
	X509Url                *url.URL           `json:"x5u,omitempty"`
	X509CertChain          []string           `json:"x5c,omitempty"`
	X509CertThumbprint     string             `json:"x5t,omitempty"`
	X509CertThumbprintS256 string             `json:"x5t#S256,omitempty"`
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
	Alg() SignatureAlgorithm
	Sign([]byte) ([]byte, error)
}

// Verifier is used to verify the signature against the payload
type Verifier interface {
	Verify([]byte, []byte) error
}

type RsaSign struct {
	Algorithm  SignatureAlgorithm
	JsonWebKey *jwk.RsaPublicKey
	KeyId      string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type EcdsaSign struct {
	Algorithm  SignatureAlgorithm
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
