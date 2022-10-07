package jwk

import (
	"context"
	"crypto"
	"sync"

	"github.com/lestrrat-go/iter/arrayiter"
	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/internal/iter"
	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

// KeyUsageType is used to denote what this key should be used for
type KeyUsageType string

const (
	// ForSignature is the value used in the headers to indicate that
	// this key should be used for signatures
	ForSignature KeyUsageType = "sig"
	// ForEncryption is the value used in the headers to indicate that
	// this key should be used for encrypting
	ForEncryption KeyUsageType = "enc"
)

type KeyOperation string
type KeyOperationList []KeyOperation

const (
	KeyOpSign       KeyOperation = "sign"       // (compute digital signature or MAC)
	KeyOpVerify     KeyOperation = "verify"     // (verify digital signature or MAC)
	KeyOpEncrypt    KeyOperation = "encrypt"    // (encrypt content)
	KeyOpDecrypt    KeyOperation = "decrypt"    // (decrypt content and validate decryption, if applicable)
	KeyOpWrapKey    KeyOperation = "wrapKey"    // (encrypt key)
	KeyOpUnwrapKey  KeyOperation = "unwrapKey"  // (decrypt key and validate decryption, if applicable)
	KeyOpDeriveKey  KeyOperation = "deriveKey"  // (derive key)
	KeyOpDeriveBits KeyOperation = "deriveBits" // (derive bits not to be used as a key)
)

// Set represents JWKS object, a collection of jwk.Key objects.
//
// Sets can be safely converted to and from JSON using the standard
// `"encoding/json".Marshal` and `"encoding/json".Unmarshal`. However,
// if you do not know if the payload contains a single JWK or a JWK set,
// consider using `jwk.Parse()` to always get a `jwk.Set` out of it.
//
// Since v1.2.12, JWK sets with private parameters can be parsed as well.
// Such private parameters can be accessed via the `Field()` method.
// If a resource contains a single JWK instead of a JWK set, private parameters
// are stored in _both_ the resulting `jwk.Set` object and the `jwk.Key` object .
//
//nolint:interfacebloat
type Set interface {
	// AddKey adds the specified key. If the key already exists in the set,
	// an error is returned.
	AddKey(Key) error

	// Clear resets the list of keys associated with this set, emptying the
	// internal list of `jwk.Key`s, as well as clearing any other non-key
	// fields
	Clear() error

	// Key returns the key at index `idx`. If the index is out of range,
	// then the second return value is false.
	Key(int) (Key, bool)

	// Get returns the value of a private field in the key set.
	//
	// For the purposes of a key set, any field other than the "keys" field is
	// considered to be a private field. In other words, you cannot use this
	// method to directly access the list of keys in the set
	Get(string, interface{}) error

	// Set sets the value of a single field.
	//
	// This method, which takes an `interface{}`, exists because
	// these objects can contain extra _arbitrary_ fields that users can
	// specify, and there is no way of knowing what type they could be.
	Set(string, interface{}) error

	// RemoveKey removes the specified non-key field from the set.
	// Keys may not be removed using this method.
	Remove(string) error

	// Index returns the index where the given key exists, -1 otherwise
	Index(Key) int

	// Len returns the number of keys in the set
	Len() int

	// LookupKeyID returns the first key matching the given key id.
	// The second return value is false if there are no keys matching the key id.
	// The set *may* contain multiple keys with the same key id. If you
	// need all of them, use `Iterate()`
	LookupKeyID(string) (Key, bool)

	// RemoveKey removes the key from the set.
	RemoveKey(Key) error

	// Keys creates an iterator to iterate through all keys in the set.
	Keys(context.Context) KeyIterator

	// Iterate creates an iterator to iterate through all fields other than the keys
	Iterate(context.Context) HeaderIterator

	// Clone create a new set with identical keys. Keys themselves are not cloned.
	Clone() (Set, error)
}

type set struct {
	keys          []Key
	mu            sync.RWMutex
	dc            dcForSet
	privateParams map[string]interface{}
}

type HeaderVisitor = iter.MapVisitor
type HeaderVisitorFunc = iter.MapVisitorFunc
type HeaderPair = mapiter.Pair
type HeaderIterator = mapiter.Iterator
type KeyPair = arrayiter.Pair
type KeyIterator = arrayiter.Iterator

type PublicKeyer interface {
	// PublicKey creates the corresponding PublicKey type for this object.
	// All fields are copied onto the new public key, except for those that are not allowed.
	// Returned value must not be the receiver itself.
	PublicKey() (Key, error)
}

type DecodeCtx = json.DecodeCtx
type keyWithDecodeCtx interface {
	SetDecodeCtx(DecodeCtx)
	DecodeCtx() DecodeCtx
}

type dcForSet interface {
	DecodeCtx
	IgnoreParseError() bool
}

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
	// Get retrieves the value of a single field.
	// The second argument must be a pointer to a suitable variable
	// that can hold the value of the specifie dfield. If you do not
	// know the type of the value, use an empty interface and a pointer
	// to it.
	Get(string, interface{}) error

	// Has returns true if the given JSON field name exists in
	// the object
	Has(string) bool

	// FieldNames returns the list of JSON field names stored in the object.
	FieldNames() []string

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

	// Clone creates a new instance of the same type
	Clone(interface{}) error

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

	// Algorithm returns the value of the `alg` field
	//
	// This field may contain either `jwk.SignatureAlgorithm`, `jwk.KeyEncryptionAlgorithm`,
	// `jwk.ContentEncryptionAlgorithm`, or `jwk.UnknownKeyAlgorithm`. Because this field
	// needs to field multiple types, the type returned is an interface
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
}
