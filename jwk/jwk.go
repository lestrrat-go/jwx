//go:generate go run internal/cmd/genheader/main.go

// Package jwk implements JWK as described in https://tools.ietf.org/html/rfc7517
package jwk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"io"
	"net/http"

	"github.com/lestrrat-go/backoff/v2"
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
//   * "crypto/rsa".PrivateKey and "crypto/rsa".PublicKey creates an RSA based key
//   * "crypto/ecdsa".PrivateKey and "crypto/ecdsa".PublicKey creates an EC based key
//   * "crypto/ed25519".PrivateKey and "crypto/ed25519".PublicKey creates an OKP based key
//   * []byte creates a symmetric key
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
// public keys of the keys contained in the set.
//
// This is useful when you are generating a set of private keys, and
// you want to generate the corresponding public versions for the
// users to verify with.
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

// Fetch fetches a JWK resource specified by a URL. The url must be
// pointing to a resource that is supported by `net/http`.
//
// If you are using the same `jwk.Set` for long periods of time during
// the lifecycle of your program, and would like to periodically refresh the
// contents of the object with the data at the remote resource,
// consider using `jwk.AutoRefresh`, which automatically refreshes
// jwk.Set objects asynchronously.
func Fetch(ctx context.Context, urlstring string, options ...FetchOption) (Set, error) {
	res, err := fetch(ctx, urlstring, options...)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	keyset, err := ParseReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, `failed to parse JWK set`)
	}
	return keyset, nil
}

func fetch(ctx context.Context, urlstring string, options ...FetchOption) (*http.Response, error) {
	var httpcl HTTPClient = http.DefaultClient
	bo := backoff.Null()
	for _, option := range options {
		switch option.Ident() {
		case identHTTPClient{}:
			httpcl = option.Value().(HTTPClient)
		case identFetchBackoff{}:
			bo = option.Value().(backoff.Policy)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlstring, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to new request to remote JWK")
	}

	b := bo.Start(ctx)
	var lastError error
	for backoff.Continue(b) {
		res, err := httpcl.Do(req)
		if err != nil {
			lastError = errors.Wrap(err, "failed to fetch remote JWK")
			continue
		}

		if res.StatusCode != http.StatusOK {
			lastError = errors.Errorf("failed to fetch remote JWK (status = %d)", res.StatusCode)
			continue
		}
		return res, nil
	}

	// It's possible for us to get here without populating lastError.
	// e.g. what if we bailed out of `for backoff.Contineu(b)` without making
	// a single request? or, <-ctx.Done() returned?
	if lastError == nil {
		lastError = errors.New(`fetching remote JWK did not complete`)
	}
	return nil, lastError
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

// ParseKey parses a single key JWK. Unlike `jwk.Parse` this method will
// report failure if you attempt to pass a JWK set. Only use this function
// when you know that the data is a single JWK.
//
// Note that a successful parsing does NOT necessarily guarantee a valid key.
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

// Parse parses JWK from the incoming []byte.
//
// For JWK sets, this is a convenience function. You could just as well
// call `json.Unmarshal` against an empty set created by `jwk.NewSet()`
// to parse a JSON buffer into a `jwk.Set`.
//
// If you know for sure that you have a single key, you could also
// use `jwk.ParseKey()`.
//
// This method exists because many times the user does not know before hand
// if a JWK(s) resource at a remote location contains a single JWK key or
// a JWK set, and `jwk.Parse()` can handle either case, returning a JWK Set
// even if the data only contains a single JWK key
func Parse(src []byte) (Set, error) {
	s := NewSet()
	if err := json.Unmarshal(src, s); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JWK set")
	}
	return s, nil
}

// ParseReader parses a JWK set from the incoming byte buffer.
func ParseReader(src io.Reader) (Set, error) {
	s := NewSet()
	if err := json.NewDecoder(src).Decode(s); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JWK set")
	}
	return s, nil
}

// ParseString parses a JWK set from the incoming string.
func ParseString(s string) (Set, error) {
	return Parse([]byte(s))
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

func cloneKey(src Key) (Key, error) {
	var dst Key
	switch src.(type) {
	case RSAPrivateKey:
		dst = NewRSAPrivateKey()
	case RSAPublicKey:
		dst = NewRSAPublicKey()
	case ECDSAPrivateKey:
		dst = NewECDSAPrivateKey()
	case ECDSAPublicKey:
		dst = NewECDSAPublicKey()
	case OKPPrivateKey:
		dst = NewOKPPrivateKey()
	case OKPPublicKey:
		dst = NewOKPPublicKey()
	case SymmetricKey:
		dst = NewSymmetricKey()
	default:
		return nil, errors.Errorf(`unknown key type %T`, src)
	}

	ctx := context.Background()
	for iter := src.Iterate(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		if err := dst.Set(pair.Key.(string), pair.Value); err != nil {
			return nil, errors.Wrapf(err, `failed to set %s`, pair.Key.(string))
		}
	}
	return dst, nil
}
