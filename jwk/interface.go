package jwk

import (
	"crypto"
	"errors"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
)

// KeyUsageType is used to denote what this key should be used for
type KeyUsageType string

const (
	// ForSignature is the value used in the headers to indicate that
	// this key should be used for signatures
	ForSignature  KeyUsageType = "sig"
	// ForEncryption is the value used in the headers to indicate that
	// this key should be used for encryptiong
	ForEncryption KeyUsageType = "enc"
)

// Errors related to JWK
var (
	ErrInvalidHeaderName  = errors.New("invalid header name")
	ErrInvalidHeaderValue = errors.New("invalid value for header key")
	ErrUnsupportedKty     = errors.New("unsupported kty")
	ErrUnsupportedCurve   = errors.New("unsupported curve")
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
	Keys []Key `json:"keys"`
}

// Key defines the minimal interface for each of the
// key types. Their use and implementation differ significantly
// between each key types, so you should use type assertions
// to perform more specific tasks with each key
type Key interface {
	Alg() string
	Kid() string
	Kty() jwa.KeyType
	Use() string

	// Set sets a value in the JWK
	Set(string, interface{}) error

	// Get retrieves the value from the JWK
	Get(string) (interface{}, error)

	// Materialize creates the corresponding key. For example,
	// RSA types would create *rsa.PublicKey or *rsa.PrivateKey,
	// EC types would create *ecdsa.PublicKey or *ecdsa.PrivateKey,
	// and OctetSeq types create a []byte key.
	Materialize() (interface{}, error)

	// Thumbprint returns the JWK thumbprint using the indicated
	// hashing algorithm, according to RFC 7638
	Thumbprint(crypto.Hash) ([]byte, error)
}

// EssentialHeader defines the common data that any Key may
// carry with it.
type EssentialHeader struct {
	// Algorithm might be any of jwa.SignatureAlgorithm or  jwa.KeyEncryptionAlgorithm
	// so it stays as string
	Algorithm              string         `json:"alg,omitempty"`
	KeyID                  string         `json:"kid,omitempty"`
	KeyOps                 []KeyOperation `json:"key_ops,omitempty"`
	KeyType                jwa.KeyType    `json:"kty,omitempty"`
	KeyUsage               string         `json:"use,omitempty"`
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

// SymmetricKey is a type of JWK generated from symmetric keys
type SymmetricKey struct {
	*EssentialHeader
	Key buffer.Buffer `json:"k"`
}

// EcdsaPublicKey is a type of JWK generated from ECDSA public keys
type EcdsaPublicKey struct {
	*EssentialHeader
	Curve jwa.EllipticCurveAlgorithm `json:"crv"`
	X     buffer.Buffer              `json:"x"`
	Y     buffer.Buffer              `json:"y"`
}

// EcdsaPrivateKey is a type of JWK generated from ECDH-ES private keys
type EcdsaPrivateKey struct {
	*EcdsaPublicKey
	D buffer.Buffer `json:"d"`
}

// EcdhesPublicKey is a type of JWK generated from ECDH-ES public keys
type EcdhesPublicKey struct {
	KeyEncryption     jwa.KeyEncryptionAlgorithm     `json:"alg"`
	ContentEncryption jwa.ContentEncryptionAlgorithm `json:"enc"`
	PublicKey         Key                            `json:"epk"`
	UInfo             buffer.Buffer                  `json:"apu,omitempty"`
	VInfo             buffer.Buffer                  `json:"apv,omitempty"`
}
