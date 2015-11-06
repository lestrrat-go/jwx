package jwe

import (
	"errors"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
)

var ErrInvalidCompactPartsCount = errors.New("compact JWE format must have five parts")

type EssentialHeader struct {
	Algorithm              jwa.KeyEncryptionAlgorithm     `json:"alg"`
	ContentEncryption      jwa.ContentEncryptionAlgorithm `json:"enc"`
	ContentType            string                         `json:"cty,omitempty"`
	Compression            jwa.CompressionAlgorithm       `json:"zip,omitempty"`
	Critical               []string                       `json:"crit,omitempty"`
	Jwk                    jwk.JSONWebKey                 `json:"jwk,omitempty"` // public key
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

type Recipient struct {
	Header       Header        `json:"header"`
	EncryptedKey buffer.Buffer `json:"encrypted_key"`
}

type Message struct {
	AdditionalAuthenticatedData buffer.Buffer `json:"aad"`
	CipherText                  buffer.Buffer `json:"ciphertext"`
	InitializationVector        buffer.Buffer `json:"iv,omitempty"`
	Protected                   buffer.Buffer `json:"protected,omitempty"`
	Recipients                  []Recipient   `json:"recipients"`
	AuthenticationTag           buffer.Buffer `json:"tag,omitempty"`
	Unprotected                 string        `json:"unprotected,omitempty"`
}
