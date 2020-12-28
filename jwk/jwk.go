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
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/iter/arrayiter"
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

// PublicKeyOf returns the corresponding public key of the given
// value `v`. For example, if v is a `*rsa.PrivateKey`, then
// `*rsa.PublicKey` is returned.
//
// Not to be confused with jwk.Key.PubliKey(). In hindsight, this should
// have been named PublicRawKeyOf() or some such.
//
// If given a public key, then the same public key will be returned.
// For example, if v is a `*rsa.PublicKey`, then the same value
// is returned.
//
// If v is of a type that we don't support, an error is returned.
//
// This is useful when you are dealing with the jwk.Key interface
// alone and you don't know before hand what the underlying key
// type is, but you still want to obtain the corresponding public key
func PublicKeyOf(v interface{}) (interface{}, error) {
	// may be a silly idea, but if the user gave us a non-pointer value...
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
func Fetch(urlstring string, options ...Option) (*Set, error) {
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

		set, err := Parse(f)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse jwk file")
		}

		for _, option := range options {
			switch option.Name() {
			case optkeyHTTPExpiration, optkeyManualExpiration:
				duration := option.Value().(time.Duration)
				set.Expires = time.Now().Add(duration)
			}
		}

		return set, nil
	}
	return nil, errors.Errorf(`invalid url scheme %s`, u.Scheme)
}

// FetchHTTP wraps FetchHTTPWithContext using the background context.
func FetchHTTP(jwkurl string, options ...Option) (*Set, error) {
	return FetchHTTPWithContext(context.Background(), jwkurl, options...)
}

// FetchHTTPWithContext fetches the remote JWK and parses its contents
func FetchHTTPWithContext(ctx context.Context, jwkurl string, options ...Option) (*Set, error) {
	httpcl := http.DefaultClient
	for _, option := range options {
		switch option.Name() {
		case optkeyHTTPClient:
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

	set, err := Parse(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse response body")
	}

	for _, option := range options {
		switch option.Name() {
		case optkeyHTTPExpiration:
			duration := option.Value().(time.Duration)
			duration = getCacheDuration(&res.Header, duration)
			set.Expires = time.Now().Add(duration)
		case optkeyManualExpiration:
			duration := option.Value().(time.Duration)
			set.Expires = time.Now().Add(duration)
		}
	}

	return set, nil
}

// getCacheDuration looks through the HTTP response headers for a cache-control
// header containing a max-age directive or an Expires header. If neither are
// found, or if the found values are less than minDuration, then minDuration is
// returned
func getCacheDuration(headers *http.Header, minDuration time.Duration) time.Duration {
	// Look for a max-age
	ccs := headers.Values("cache-control")
	for _, cc := range ccs {
		directives := strings.Split(cc, ",")
		for _, directive := range directives {
			kvp := strings.Split(directive, "=")
			if len(kvp) != 2 {
				continue
			}
			if strings.ToLower(strings.TrimSpace(kvp[0])) == "max-age" {
				i, err := strconv.ParseInt(strings.TrimSpace(kvp[1]), 10, 32)
				if err != nil || i < 0 {
					continue
				}

				duration := time.Second * time.Duration(i)
				if duration > minDuration {
					return duration
				}

				// Found a max-age, but didn't use it. We can stop
				return minDuration
			}
		}
	}

	// Look for an Expires header, only if max-age didn't exist
	expires := strings.TrimSpace(headers.Get("expires"))
	if expires != "" {
		// Try to parse it
		t, err := http.ParseTime(expires)
		if err == nil {
			duration := time.Until(t)
			if duration > minDuration {
				return duration
			}
		}
	}

	// Couldn't find an usable expiration
	return minDuration
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

func (s *Set) UnmarshalJSON(data []byte) error {
	var proxy struct {
		Keys []json.RawMessage `json:"keys"`
	}

	if err := json.Unmarshal(data, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmarshal into Key (proxy)`)
	}

	if len(proxy.Keys) == 0 {
		k, err := ParseKey(data)
		if err != nil {
			return errors.Wrap(err, `failed to unmarshal key from JSON headers`)
		}
		s.Keys = append(s.Keys, k)
	} else {
		for i, buf := range proxy.Keys {
			k, err := ParseKey([]byte(buf))
			if err != nil {
				return errors.Wrapf(err, `failed to unmarshal key #%d (total %d) from multi-key JWK set`, i+1, len(proxy.Keys))
			}
			s.Keys = append(s.Keys, k)
		}
	}
	return nil
}

// Parse parses JWK from the incoming io.Reader. This function can handle
// both single-key and multi-key formats. If you know before hand which
// format the incoming data is in, you might want to consider using
// "github.com/lestrrat-go/jwx/internal/json" directly
//
// Note that a successful parsing does NOT guarantee a valid key
func Parse(in io.Reader) (*Set, error) {
	var s Set
	if err := json.NewDecoder(in).Decode(&s); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JWK")
	}
	return &s, nil
}

// ParseBytes parses JWK from the incoming byte buffer.
//
// Note that a successful parsing does NOT guarantee a valid key
func ParseBytes(buf []byte) (*Set, error) {
	return Parse(bytes.NewReader(buf))
}

// ParseString parses JWK from the incoming string.
//
// Note that a successful parsing does NOT guarantee a valid key
func ParseString(s string) (*Set, error) {
	return Parse(strings.NewReader(s))
}

// LookupKeyID looks for keys matching the given key id. Note that the
// Set *may* contain multiple keys with the same key id
func (s Set) LookupKeyID(kid string) []Key {
	var keys []Key
	for iter := s.Iterate(context.TODO()); iter.Next(context.TODO()); {
		pair := iter.Pair()
		key := pair.Value.(Key)
		if key.KeyID() == kid {
			keys = append(keys, key)
		}
	}
	return keys
}

func (s *Set) Len() int {
	return len(s.Keys)
}

func (s *Set) Iterate(ctx context.Context) KeyIterator {
	ch := make(chan *KeyPair, s.Len())
	go iterate(ctx, s.Keys, ch)
	return arrayiter.New(ch)
}

// IsExpired returns true if the
func (s *Set) IsExpired() bool {
	if s.Expires.IsZero() {
		return false
	}

	return time.Now().After(s.Expires)
}

func iterate(ctx context.Context, keys []Key, ch chan *KeyPair) {
	defer close(ch)

	for i, key := range keys {
		pair := &KeyPair{Index: i, Value: key}
		select {
		case <-ctx.Done():
			return
		case ch <- pair:
		}
	}
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
		switch option.Name() {
		case optkeyThumbprintHash:
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
