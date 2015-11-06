package jwk

import (
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
)

type KeyOperation string

const (
	KeyOpSign       KeyOperation = "sign"       // (compute digital signature or MAC)
	KeyOpVerify                  = "verify"     // (verify digital signature or MAC)
	KeyOpEncrypt                 = "encrypt"    // (encrypt content)
	KeyOpDecrypt                 = "decrypt"    // (decrypt content and validate decryption, if applicable)
	KeyOpWrapKey                 = "wrapKey"    // (encrypt key)
	KeyOpUnwrapKey               = "unwrapKey"  // (decrypt key and validate decryption, if applicable)
	KeyOpDeriveKey               = "deriveKey"  // (derive key)
	KeyOpDeriveBits              = "deriveBits" // (derive bits not to be used as a key)
)

// Set is a convenience struct to allow generating and parsing
// JWK sets as opposed to single JWKs
type Set struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey defines the minimal interface for each of the
// key types. Their use and implementation differ significantly
// between each key types, so you should use type assertions
// to perform more specific tasks with each key
type JSONWebKey interface {
	Kid() string
	Kty() string
}

// EssentialHeader defines the common data that any JSONWebKey may
// carry with it.
type EssentialHeader struct {
	Algorithm              string         `json:"alg,omitempty"`
	KeyID                  string         `json:"kid,omitempty"`
	KeyOps                 []KeyOperation `json:"key_ops,omitempty"`
	KeyType                string         `json:"kty,omitempty"`
	Use                    string         `json:"use,omitempty"`
	X509Url                *url.URL       `json:"x5u,omitempty"`
	X509CertChain          []string       `json:"x5c,omitempty"`
	X509CertThumbprint     string         `json:"x5t,omitempty"`
	X509CertThumbprintS256 string         `json:"x5t#S256,omitempty"`
}

// RsaPublicKey is a type of JWK generated from RSA public keys
type RsaPublicKey struct {
	*EssentialHeader
	E buffer.Buffer `json:"e"`
	N buffer.Buffer `json:"n"`
}

// RsaPrivateKey is a type of JWK generated from RSA private keys
type RsaPrivateKey struct {
	*RsaPublicKey
	D  buffer.Buffer `json:"d"`
	P  buffer.Buffer `json:"p"`
	Q  buffer.Buffer `json:"q"`
	Dp buffer.Buffer `json:"dp,omitempty"`
	Dq buffer.Buffer `json:"dq,omitempty"`
	Qi buffer.Buffer `json:"qi,omitempty"`
}
