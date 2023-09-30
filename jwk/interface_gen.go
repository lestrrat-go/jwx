// Code generated by tools/cmd/genjwk/main.go. DO NOT EDIT.

package jwk

import (
	"crypto"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

const (
	KeyTypeKey                = "kty"
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

	// Has returns true if the specified field has a value, even if
	// the value is empty-ish (e.g. 0, false, "")  as long as it has been
	// explicitly set.
	Has(string) bool

	// Get is used to extract the value of any field, including non-standard fields, out of the key.
	//
	// The first argument is the name of the field. The second argument is a pointer
	// to a variable that will receive the value of the field. The method returns
	// an error if the field does not exist, or if the value cannot be assigned to
	// the destination variable. Note that a field is considered to "exist" even if
	// the value is empty-ish (e.g. 0, false, ""), as long as it is explicitly set.
	Get(string, interface{}) error

	// Set sets the value of a single field. Note that certain fields,
	// notably "kty", cannot be altered, but will not return an error
	//
	// This method, which takes an `interface{}`, exists because
	// these objects can contain extra _arbitrary_ fields that users can
	// specify, and there is no way of knowing what type they could be
	Set(string, interface{}) error

	// Remove removes the field associated with the specified key.
	// There is no way to remove the `kty` (key type). You will ALWAYS be left with one field in a jwk.Key.
	Remove(string) error

	// Raw creates the corresponding raw key. For example,
	// EC types would create *ecdsa.PublicKey or *ecdsa.PrivateKey,
	// and OctetSeq types create a []byte key.
	//
	// If you do not know the exact type of a jwk.Key before attempting
	// to obtain the raw key, you can simply pass a pointer to an
	// empty interface as the first argument.
	//
	// If you already know the exact type, it is recommended that you
	// pass a pointer to the zero value of the actual key type (e.g. &rsa.PrivateKey)
	// for efficiency.
	Raw(interface{}) error

	// Thumbprint returns the JWK thumbprint using the indicated
	// hashing algorithm, according to RFC 7638
	Thumbprint(crypto.Hash) ([]byte, error)

	// Keys returns a list of the keys contained in this jwk.Key.
	Keys() []string

	// Clone creates a new instance of the same type
	Clone() (Key, error)

	// PublicKey creates the corresponding PublicKey type for this object.
	// All fields are copied onto the new public key, except for those that are not allowed.
	//
	// If the key is already a public key, it returns a new copy minus the disallowed fields as above.
	PublicKey() (Key, error)

	// KeyType returns the `kty` of a JWK
	KeyType() jwa.KeyType
	// KeyUsage returns `use` of a JWK
	KeyUsage() string
	// KeyOps returns `key_ops` of a JWK
	KeyOps() KeyOperationList
	// Algorithm returns `alg` of a JWK

	// Algorithm returns the value of the `alg` field
	//
	// This field may contain either `jwk.SignatureAlgorithm` or `jwk.KeyEncryptionAlgorithm`.
	// This is why there exists a `jwa.KeyAlgorithm` type that encompases both types.
	Algorithm() jwa.KeyAlgorithm
	// KeyID returns `kid` of a JWK
	KeyID() string
	// X509URL returns `x5u` of a JWK
	X509URL() string
	// X509CertChain returns `x5c` of a JWK
	X509CertChain() *cert.Chain
	// X509CertThumbprint returns `x5t` of a JWK
	X509CertThumbprint() string
	// X509CertThumbprintS256 returns `x5t#S256` of a JWK
	X509CertThumbprintS256() string

	makePairs() []*HeaderPair
}
