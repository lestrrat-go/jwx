package jws

import (
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
)

type EncodedSignature struct {
	Protected string          `json:"protected,omitempty"`
	Headers   HeaderInterface `json:"header,omitempty"`
	Signature string          `json:"signature,omitempty"`
}

type encodedSignatureUnmarshalProxy struct {
	Protected string           `json:"protected,omitempty"`
	Headers   *StandardHeaders `json:"header,omitempty"`
	Signature string           `json:"signature,omitempty"`
}

type EncodedMessage struct {
	Payload    string              `json:"payload"`
	Signatures []*EncodedSignature `json:"signatures,omitempty"`
}

type encodedMessageUnmarshalProxy struct {
	Payload    string                            `json:"payload"`
	Signatures []*encodedSignatureUnmarshalProxy `json:"signatures,omitempty"`
}

type FullEncodedMessage struct {
	*EncodedSignature // embedded to pick up flattened JSON message
	*EncodedMessage
}

type fullEncodedMessageUnmarshalProxy struct {
	*encodedSignatureUnmarshalProxy // embedded to pick up flattened JSON message
	*encodedMessageUnmarshalProxy
}

// EssentialHeader is a set of headers that are already defined in RFC 7515
type EssentialHeader struct {
	Algorithm              jwa.SignatureAlgorithm `json:"alg,omitempty"`
	ContentType            string                 `json:"cty,omitempty"`
	Critical               []string               `json:"crit,omitempty"`
	Jwk                    jwk.Key                `json:"jwk,omitempty"` // public key
	JwkSetURL              *url.URL               `json:"jku,omitempty"`
	KeyID                  string                 `json:"kid,omitempty"`
	Type                   string                 `json:"typ,omitempty"` // e.g. "JWT"
	X509Url                *url.URL               `json:"x5u,omitempty"`
	X509CertChain          []string               `json:"x5c,omitempty"`
	X509CertThumbprint     string                 `json:"x5t,omitempty"`
	X509CertThumbprintS256 string                 `json:"x5t#S256,omitempty"`
}

// Header represents a JWS header.
type Header struct {
	*EssentialHeader `json:"-"`
	PrivateParams    map[string]interface{} `json:"-"`
}

// EncodedHeader represents a header value that is base64 encoded
// in JSON format
type EncodedHeader struct {
	*Header
	// This is a special field. It's ONLY set when parsed from a serialized form.
	// It's used for verification purposes, because header representations (such as
	// JSON key order) may differ from what the source encoded with and what the
	// go json package uses
	//
	// If this field is populated (Len() > 0), it will be used for signature
	// calculation.
	// If you change the header values, make sure to clear this field, too
	Source buffer.Buffer `json:"-"`
}

// PayloadSigner generates signature for the given payload
type PayloadSigner interface {
	Sign([]byte) ([]byte, error)
	Algorithm() jwa.SignatureAlgorithm
	ProtectedHeader() HeaderInterface
	PublicHeader() HeaderInterface
}

// MergedHeader is a provides an interface to query both protected
// and public headers
type MergedHeader struct {
	ProtectedHeader *EncodedHeader
	PublicHeader    *Header
}

// Message represents a full JWS encoded message. Flattened serialization
// is not supported as a struct, but rather it's represented as a
// Message struct with only one `signature` element.
//
// Do not expect to use the Message object to verify or construct a
// signed payloads with. You should only use this when you want to actually
// want to programatically view the contents for the full JWS payload.
//
// To sign and verify, use the appropriate `Sign()` nad `Verify()` functions
type Message struct {
	payload    []byte       `json:"payload"`
	signatures []*Signature `json:"signatures,omitempty"`
}

type Signature struct {
	headers   HeaderInterface `json:"header,omitempty"`    // Unprotected Heders
	protected HeaderInterface `json:"protected,omitempty"` // Protected Headers
	signature []byte          `json:"signature,omitempty"` // Signature
}

// JWKAcceptor decides which keys can be accepted
// by functions that iterate over a JWK key set.
type JWKAcceptor interface {
	Accept(jwk.Key) bool
}

// JWKAcceptFunc is an implementation of JWKAcceptor
// using a plain function
type JWKAcceptFunc func(jwk.Key) bool

// Accept executes the provided function to determine if the
// given key can be used
func (f JWKAcceptFunc) Accept(key jwk.Key) bool {
	return f(key)
}

// DefaultJWKAcceptor is the default acceptor that is used
// in functions like VerifyWithJWKSet
var DefaultJWKAcceptor = JWKAcceptFunc(func(key jwk.Key) bool {
	if u := key.Use(); u != "" && u != "enc" && u != "sig" {
		return false
	}
	return true
})
