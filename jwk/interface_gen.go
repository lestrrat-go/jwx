// This file is auto-generated. DO NOT EDIT

package jwk

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/lestrrat-go/jwx/jwa"
)

const (
	KeyUsageKey               = "use"
	KeyOpsKey                 = "key_ops"
	AlgorithmKey              = "alg"
	KeyIDKey                  = "kid"
	X509URLKey                = "x5u"
	X509CertChainKey          = "x5c"
	X509CertThumbprintKey     = "x5t"
	X509CertThumbprintS256Key = "x5t#S256"
)

// Key defines the minimal interface for each of the
// key types. Their use and implementation differ significantly
// between each key types, so you should use type assertions
// to perform more specific tasks with each key
type Key interface {
	// Get returns the value of a single field. The second boolean argument
	// will be false if the field is not stored in the source
	Get(string) (interface{}, bool)

	// Set sets the value of a single field. Note that certain fields,
	// notable "kty" cannot be altered, but will not return an error
	Set(string, interface{}) error

	// Materialize creates the corresponding key. For example,
	// EC types would create *ecdsa.PublicKey or *ecdsa.PrivateKey,
	// and OctetSeq types create a []byte key.
	Materialize(interface{}) error

	// Thumbprint returns the JWK thumbprint using the indicated
	// hashing algorithm, according to RFC 7638
	Thumbprint(crypto.Hash) ([]byte, error)

	// FromRaw is used to initialize a key from its corresponding "raw"
	// key: e.g. RSAPublicKey can be initialized using *rsa.PublicKey,
	// ECDSAPrivateKey can be initialized using *ecdsa.PrivateKey, etc.
	FromRaw(interface{}) error

	// Iterate returns an iterator that returns all keys and values
	Iterate(ctx context.Context) HeaderIterator

	// Walk is a utility tool that allows a visitor to iterate all keys and values
	Walk(context.Context, HeaderVisitor) error

	// AsMap is a utility tool returns a map that contains the same fields as the source
	AsMap(context.Context) (map[string]interface{}, error)

	// PrivateParams returns the non-standard elements in the source structure
	PrivateParams() map[string]interface{}

	KeyType() jwa.KeyType
	KeyUsage() string
	KeyOps() KeyOperationList
	Algorithm() string
	KeyID() string
	X509URL() string
	X509CertChain() []*x509.Certificate
	X509CertThumbprint() string
	X509CertThumbprintS256() string
}
