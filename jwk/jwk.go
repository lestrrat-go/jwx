//go:generate go run internal/cmd/genheader/main.go

// Package jwk implements JWK as described in https://tools.ietf.org/html/rfc7517
package jwk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/lestrrat-go/iter/arrayiter"
	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

// New creates a jwk.Key from the given key (RSA/ECDSA/symmetric keys).
func New(key interface{}) (Key, error) {
	if key == nil {
		return nil, errors.New(`jwk.New requires a non-nil key`)
	}

	switch v := key.(type) {
	case rsa.PrivateKey:
		return newRSAPrivateKey(&v) // force pointer
	case *rsa.PrivateKey:
		return newRSAPrivateKey(v)
	case rsa.PublicKey:
		return newRSAPublicKey(&v) // force pointer
	case *rsa.PublicKey:
		return newRSAPublicKey(v)
	case ecdsa.PrivateKey:
		return newECDSAPrivateKey(&v) // force pointer
	case *ecdsa.PrivateKey:
		return newECDSAPrivateKey(v)
	case ecdsa.PublicKey:
		return newECDSAPublicKey(&v) // force pointer
	case *ecdsa.PublicKey:
		return newECDSAPublicKey(v)
	case []byte:
		return newSymmetricKey(v)
	default:
		return nil, errors.Errorf(`invalid key type '%T' for jwk.New`, key)
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

		return Parse(f)
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

	return Parse(res.Body)
}

func unmarshalKey(data []byte) (Key, error) {
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
			key = &RSAPrivateKey{}
		} else {
			key = &RSAPublicKey{}
		}
	case jwa.EC:
		if len(hint.D) > 0 {
			key = &ECDSAPrivateKey{}
		} else {
			key = &ECDSAPublicKey{}
		}
	case jwa.OctetSeq:
		key = &SymmetricKey{}
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
		k, err := unmarshalKey(data)
		if err != nil {
			return errors.Wrap(err, `failed to unmarshal key from JSON headers`)
		}
		s.Keys = append(s.Keys, k)
	} else {
		for i, buf := range proxy.Keys {
			data = []byte(buf)
			k, err := unmarshalKey(data)
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
// "encoding/json" directly
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
	for _, key := range s.Keys {
		if key.KeyID() == kid {
			keys = append(keys, key)
		}
	}
	return keys
}

func (s *Set) Len() int {
	return len(s.Keys)
}

// helper for x5c handling
func marshalX509CertChain(chain []*x509.Certificate) []string {
	encodedCerts := make([]string, len(chain))
	for idx, cert := range chain {
		// XXX does this need to be StdEncoding? can it be RawURL?
		encodedCerts[idx] = base64.EncodeToStringStd(cert.Raw)
	}
	return encodedCerts
}

func (s *Set) Iterate(ctx context.Context) KeyIterator {
	ch := make(chan *KeyPair, s.Len())
	go iterate(ctx, s.Keys, ch)
	return arrayiter.New(ch)
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
