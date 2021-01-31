package jws

import (
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/internal/iter"
	"github.com/lestrrat-go/jwx/jwa"
)

// Message represents a full JWS encoded message. Flattened serialization
// is not supported as a struct, but rather it's represented as a
// Message struct with only one `signature` element.
//
// Do not expect to use the Message object to verify or construct a
// signed payload with. You should only use this when you want to actually
// programmatically view the contents of the full JWS payload.
//
// To sign and verify, use the appropriate `Sign()` and `Verify()` functions.
type Message struct {
	payload    []byte
	signatures []*Signature
}

type Signature struct {
	headers   Headers // Unprotected Headers
	protected Headers // Protected Headers
	signature []byte  // Signature
}

type Visitor = iter.MapVisitor
type VisitorFunc = iter.MapVisitorFunc
type HeaderPair = mapiter.Pair
type Iterator = mapiter.Iterator

// Signer generates the signature for a given payload.
type Signer interface {
	// Sign creates a signature for the given payload.
	// The scond argument is the key used for signing the payload, and is usually
	// the private key type associated with the signature method. For example,
	// for `jwa.RSXXX` and `jwa.PSXXX` types, you need to pass the
	// `*"crypto/rsa".PrivateKey` type.
	// Check the documentation for each signer for details
	Sign([]byte, interface{}) ([]byte, error)

	Algorithm() jwa.SignatureAlgorithm
}

type rsaSignFunc func([]byte, *rsa.PrivateKey) ([]byte, error)

// RSASigner uses crypto/rsa to sign the payloads.
type RSASigner struct {
	alg  jwa.SignatureAlgorithm
	sign rsaSignFunc
}

type ecdsaSignFunc func([]byte, *ecdsa.PrivateKey) ([]byte, error)

// ECDSASigner uses crypto/ecdsa to sign the payloads.
type ECDSASigner struct {
	alg  jwa.SignatureAlgorithm
	sign ecdsaSignFunc
}

type hmacSignFunc func([]byte, []byte) ([]byte, error)

// HMACSigner uses crypto/hmac to sign the payloads.
type HMACSigner struct {
	alg  jwa.SignatureAlgorithm
	sign hmacSignFunc
}

type EdDSASigner struct {
}

type Verifier interface {
	// Verify checks whether the payload and signature are valid for
	// the given key.
	// `key` is the key used for verifying the payload, and is usually
	// the public key associated with the signature method. For example,
	// for `jwa.RSXXX` and `jwa.PSXXX` types, you need to pass the
	// `*"crypto/rsa".PublicKey` type.
	// Check the documentation for each verifier for details
	Verify(payload []byte, signature []byte, key interface{}) error
}

type rsaVerifyFunc func([]byte, []byte, *rsa.PublicKey) error

type RSAVerifier struct {
	verify rsaVerifyFunc
}

type ecdsaVerifyFunc func([]byte, []byte, *ecdsa.PublicKey) error

type ECDSAVerifier struct {
	verify ecdsaVerifyFunc
}

type HMACVerifier struct {
	signer Signer
}

type EdDSAVerifier struct {
}
