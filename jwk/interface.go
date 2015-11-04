package jwk

import (
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
)

// rawKey is used to parse through the JSON object from which to
// construct the actual JWK's. The only reason this exists is to
// allow the parser to decide which type of key to create based
// upon which keys are present in the parsed JSON object
type rawKey map[string]interface{}

// Set is a convenience struct to allow generating and parsing
// JWK sets as opposed to single JWKs
type Set struct {
	Keys []JsonWebKey `json:"keys"`
}

// JsonWebKey defines the minimal interface for each of the
// key types. Their use and implementation differ significantly
// between each key types, so you should use type assertions
// to perform more specific tasks with each key
type JsonWebKey interface {
	Kid() string
	Kty() string
}

// Essential defines the common data that any JsonWebKey may
// carry with it.
type Essential struct {
	Algorithm                     string   `json:"alg,omitempty"`
	KeyId                         string   `json:"kid,omitempty"`
	KeyOps                        []string `json:"key_ops,omitempty"`
	KeyType                       string   `json:"kty,omitempty"`
	Use                           string   `json:"use,omitempty"`
	X509Url                       *url.URL `json:"x5u,omitempty"`
	X509CertificateChain          []string `json:"x5c,omitempty"`
	X509CertificateThumbprint     string   `json:"x5t,omitempty"`
	X509CertificateThumbprintS256 string   `json:"x5t#S256,omitempty"`
}

// RsaPublicKey is a type of JWK generated from RSA public keys
type RsaPublicKey struct {
	*Essential
	E buffer.Buffer `json:"e"`
	N buffer.Buffer `json:"n"`
}

// RsaPrivateKey is a type of JWK generated from RSA private keys
type RsaPrivateKey struct {
	*RsaPublicKey
	D buffer.Buffer `json:"d"`
	P buffer.Buffer `json:"p"`
	Q buffer.Buffer `json:"q"`
}
