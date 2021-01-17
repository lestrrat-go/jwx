package jwk

import (
	"context"
	"crypto/x509"
	"sync"

	"github.com/lestrrat-go/iter/arrayiter"
	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/internal/iter"
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

type CertificateChain struct {
	certs []*x509.Certificate
}

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

// Set represents JWKS object, a collection of jwk.Key objects
type Set interface {
	Add(Key) bool
	Clear()
	Get(int) (Key, bool)
	Index(Key) int
	Len() int
	LookupKeyID(string) (Key, bool)
	Remove(Key) bool
	Iterate(context.Context) KeyIterator
}

type set struct {
	keys []Key
	mu   sync.RWMutex
}

type HeaderVisitor = iter.MapVisitor
type HeaderVisitorFunc = iter.MapVisitorFunc
type HeaderPair = mapiter.Pair
type HeaderIterator = mapiter.Iterator
type KeyPair = arrayiter.Pair
type KeyIterator = arrayiter.Iterator

type AutoRefreshOption interface {
	Option
	autoRefreshOptionMarker
}

type autoRefreshOptionMarker interface {
	autoRefreshOption() bool
}

type PublicKeyer interface {
	// PublicKey creates the corresponding PublicKey type for this object.
	// All fields are copied onto the new public key, except for those that are not allowed.
	// Returned value must not be the receiver itself.
	PublicKey() (Key, error)
}
