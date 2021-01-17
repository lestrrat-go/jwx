//go:generate go run internal/cmd/genheader/main.go

// Package jwk implements JWK as described in https://tools.ietf.org/html/rfc7517
package jwk

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/x25519"
	"github.com/pkg/errors"
)

// New creates a jwk.Key from the given key (RSA/ECDSA/symmetric keys).
//
// The constructor auto-detects the type of key to be instantiated
// based on the input type:
//
// * "crypto/rsa".PrivateKey and "crypto/rsa".PublicKey creates an RSA based key
// * "crypto/ecdsa".PrivateKey and "crypto/ecdsa".PublicKey creates an EC based key
// * "crypto/ed25519".PrivateKey and "crypto/ed25519".PublicKey creates an OKP based key
// * []byte creates a symmetric key
func New(key interface{}) (Key, error) {
	if key == nil {
		return nil, errors.New(`jwk.New requires a non-nil key`)
	}

	var ptr interface{}
	switch v := key.(type) {
	case rsa.PrivateKey:
		ptr = &v
	case rsa.PublicKey:
		ptr = &v
	case ecdsa.PrivateKey:
		ptr = &v
	case ecdsa.PublicKey:
		ptr = &v
	default:
		ptr = v
	}

	switch rawKey := ptr.(type) {
	case *rsa.PrivateKey:
		k := NewRSAPrivateKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, errors.Wrapf(err, `failed to initialize %T from %T`, k, rawKey)
		}
		return k, nil
	case *rsa.PublicKey:
		k := NewRSAPublicKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, errors.Wrapf(err, `failed to initialize %T from %T`, k, rawKey)
		}
		return k, nil
	case *ecdsa.PrivateKey:
		k := NewECDSAPrivateKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, errors.Wrapf(err, `failed to initialize %T from %T`, k, rawKey)
		}
		return k, nil
	case *ecdsa.PublicKey:
		k := NewECDSAPublicKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, errors.Wrapf(err, `failed to initialize %T from %T`, k, rawKey)
		}
		return k, nil
	case ed25519.PrivateKey:
		k := NewOKPPrivateKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, errors.Wrapf(err, `failed to initialize %T from %T`, k, rawKey)
		}
		return k, nil
	case ed25519.PublicKey:
		k := NewOKPPublicKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, errors.Wrapf(err, `failed to initialize %T from %T`, k, rawKey)
		}
		return k, nil
	case x25519.PrivateKey:
		k := NewOKPPrivateKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, errors.Wrapf(err, `failed to initialize %T from %T`, k, rawKey)
		}
		return k, nil
	case x25519.PublicKey:
		k := NewOKPPublicKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, errors.Wrapf(err, `failed to initialize %T from %T`, k, rawKey)
		}
		return k, nil
	case []byte:
		k := NewSymmetricKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, errors.Wrapf(err, `failed to initialize %T from %T`, k, rawKey)
		}
		return k, nil
	default:
		return nil, errors.Errorf(`invalid key type '%T' for jwk.New`, key)
	}
}

// PublicSetOf returns a new jwk.Set consisting of
// public keys of the keys contained in the set are returned.
//
// This is useful when you are generating a set of private keys, and
// you want to generate the corresponding public versions
//
// Be aware that all fields will be copied onto the new public key. It is the caller's
// responsibility to remove any fields, if necessary.
func PublicSetOf(v Set) (Set, error) {
	newSet := NewSet()

	for iter := v.Iterate(context.TODO()); iter.Next(context.TODO()); {
		pair := iter.Pair()
		pubKey, err := PublicKeyOf(pair.Value.(Key))
		if err != nil {
			return nil, errors.Wrapf(err, `failed to get public key of %T`, pair.Value)
		}
		newSet.Add(pubKey)
	}

	return newSet, nil
}

// PublicKeyOf returns the corresponding public version of the jwk.Key.
// If `v` is a SymmetricKey, then the same value is returned.
// If `v` is already a public key, the key itself is returned.
//
// If `v` is a private key type that has a `PublicKey()` method, be aware
// that all fields will be copied onto the new public key. It is the caller's
// responsibility to remove any fields, if necessary
func PublicKeyOf(v Key) (Key, error) {
	switch v := v.(type) {
	case PublicKeyer:
		return v.PublicKey()
	default:
		return nil, errors.Errorf(`unknown jwk.Key type %T`, v)
	}
}

// PublicRawKeyOf returns the corresponding public key of the given
// value `v` (e.g. given *rsa.PrivateKey, *rsa.PublicKey is returned)
// If `v` is already a public key, the key itself is returned.
// The returned value will always be a pointer to the public key,
// except when a []byte (e.g. symmetric key, ed25519 key) is passed to `v`.
// In this case, the same []byte value is returned.
func PublicRawKeyOf(v interface{}) (interface{}, error) {
	// This may be a silly idea, but if the user gave us a non-pointer value...
	var ptr interface{}
	switch v := v.(type) {
	case rsa.PrivateKey:
		ptr = &v
	case rsa.PublicKey:
		ptr = &v
	case ecdsa.PrivateKey:
		ptr = &v
	case ecdsa.PublicKey:
		ptr = &v
	default:
		ptr = v
	}

	switch x := ptr.(type) {
	case *rsa.PrivateKey:
		return &x.PublicKey, nil
	case *rsa.PublicKey:
		return x, nil
	case *ecdsa.PrivateKey:
		return &x.PublicKey, nil
	case *ecdsa.PublicKey:
		return x, nil
	case ed25519.PrivateKey:
		return x.Public(), nil
	case ed25519.PublicKey:
		return x, nil
	case x25519.PrivateKey:
		return x.Public(), nil
	case x25519.PublicKey:
		return x, nil
	case []byte:
		return x, nil
	default:
		return nil, errors.Errorf(`invalid key type passed to PublicKeyOf (%T)`, v)
	}
}

// Fetch fetches a JWK resource specified by a URL
func Fetch(urlstring string, options ...Option) (Set, error) {
	u, err := url.Parse(urlstring)
	if err != nil {
		return nil, errors.Wrap(err, `failed to parse url`)
	}

	switch u.Scheme {
	case "http", "https":
		return FetchHTTP(urlstring, options...)
	case "file":
		f, err := os.Open(u.Path)
		if err != nil {
			return nil, errors.Wrap(err, `failed to open jwk file`)
		}
		defer f.Close()

		return Parse(f)
	}
	return nil, errors.Errorf(`invalid url scheme %s`, u.Scheme)
}

// FetchHTTP wraps FetchHTTPWithContext using the background context.
func FetchHTTP(jwkurl string, options ...Option) (Set, error) {
	return FetchHTTPWithContext(context.Background(), jwkurl, options...)
}

// FetchHTTPWithContext fetches the remote JWK and parses its contents
func FetchHTTPWithContext(ctx context.Context, jwkurl string, options ...Option) (Set, error) {
	httpcl := http.DefaultClient
	for _, option := range options {
		switch option.Ident() {
		case identHTTPClient{}:
			httpcl = option.Value().(*http.Client)
		}
	}

	req, err := http.NewRequest(http.MethodGet, jwkurl, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to new request to remote JWK")
	}

	res, err := httpcl.Do(req.WithContext(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch remote JWK")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch remote JWK (status = %d)", res.StatusCode)
	}

	return Parse(res.Body)
}

// ParseRawKey is a combination of ParseKey and Raw. It parses a single JWK key,
// and assigns the "raw" key to the given parameter. The key must either be
// a pointer to an empty interface, or a pointer to the actual raw key type
// such as *rsa.PrivateKey, *ecdsa.PublicKey, *[]byte, etc.
func ParseRawKey(data []byte, rawkey interface{}) error {
	key, err := ParseKey(data)
	if err != nil {
		return errors.Wrap(err, `failed to parse key`)
	}

	if err := key.Raw(rawkey); err != nil {
		return errors.Wrap(err, `failed to assign to raw key variable`)
	}

	return nil
}

// ParseKey parses a single key JWK. This method will report failure for
// JWK with multiple keys, even if the JWK is valid: You must specify a single
// key only.
func ParseKey(data []byte) (Key, error) {
	var hint struct {
		Kty string          `json:"kty"`
		D   json.RawMessage `json:"d"`
	}

	if err := json.Unmarshal(data, &hint); err != nil {
		return nil, errors.Wrap(err, `failed to unmarshal JSON into key hint`)
	}

	var key Key
	switch jwa.KeyType(hint.Kty) {
	case jwa.RSA:
		if len(hint.D) > 0 {
			key = newRSAPrivateKey()
		} else {
			key = newRSAPublicKey()
		}
	case jwa.EC:
		if len(hint.D) > 0 {
			key = newECDSAPrivateKey()
		} else {
			key = newECDSAPublicKey()
		}
	case jwa.OctetSeq:
		key = newSymmetricKey()
	case jwa.OKP:
		if len(hint.D) > 0 {
			key = newOKPPrivateKey()
		} else {
			key = newOKPPublicKey()
		}
	default:
		return nil, errors.Errorf(`invalid key type from JSON (%s)`, hint.Kty)
	}

	if err := json.Unmarshal(data, key); err != nil {
		return nil, errors.Wrapf(err, `failed to unmarshal JSON into key (%T)`, key)
	}

	return key, nil
}

// Parse parses JWK from the incoming io.Reader. This function can handle
// both single-key and multi-key formats. If you know before hand which
// format the incoming data is in, you might want to consider using
// "github.com/lestrrat-go/jwx/internal/json" directly
//
// Note that a successful parsing does NOT guarantee a valid key
//
// Parse will be removed in v1.1.0.
// v1.1.0 will introduce `Parse([]byte)` and `ParseReader(`io.Reader`)
func Parse(in io.Reader) (Set, error) {
	s := NewSet()
	if err := json.NewDecoder(in).Decode(s); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JWK")
	}
	return s, nil
}

// ParseBytes parses JWK from the incoming byte buffer.
//
// Note that a successful parsing does NOT guarantee a valid key
//
// ParseBytes will be removed in v1.1.0.
// v1.1.0 will introduce `Parse([]byte)` and `ParseReader(`io.Reader`)
func ParseBytes(buf []byte) (Set, error) {
	return Parse(bytes.NewReader(buf))
}

// ParseString parses JWK from the incoming string.
//
// Note that a successful parsing does NOT guarantee a valid key
//
// ParseString will be removed in v1.1.0.
// v1.1.0 will introduce `Parse([]byte)` and `ParseReader(`io.Reader`)
func ParseString(s string) (Set, error) {
	return Parse(strings.NewReader(s))
}

// AssignKeyID is a convenience function to automatically assign the "kid"
// section of the key, if it already doesn't have one. It uses Key.Thumbprint
// method with crypto.SHA256 as the default hashing algorithm
func AssignKeyID(key Key, options ...Option) error {
	if _, ok := key.Get(KeyIDKey); ok {
		return nil
	}

	hash := crypto.SHA256
	for _, option := range options {
		switch option.Ident() {
		case identThumbprintHash{}:
			hash = option.Value().(crypto.Hash)
		}
	}

	h, err := key.Thumbprint(hash)
	if err != nil {
		return errors.Wrap(err, `failed to generate thumbprint`)
	}

	if err := key.Set(KeyIDKey, base64.EncodeToString(h)); err != nil {
		return errors.Wrap(err, `failed to set "kid"`)
	}

	return nil
}
