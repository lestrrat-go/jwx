//go:generate go run internal/cmd/gentoken/main.go

// Package jwt implements JSON Web Tokens as described in https://tools.ietf.org/html/rfc7519
package jwt

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/pkg/errors"
)

// ParseString calls Parse with the given string
func ParseString(s string) (*Token, error) {
	return Parse(strings.NewReader(s))
}

// ParseString calls Parse with the given byte sequence
func ParseBytes(s []byte) (*Token, error) {
	return Parse(bytes.NewReader(s))
}

// Parse parses the JWT token payload and creates a new `jwt.Token` object.
// The token must be encoded in either JSON or compact format, with a valid
// signature. If the signature is invalid, this method return an error
func Parse(src io.Reader) (*Token, error) {
	m, err := jws.Parse(src)
	if err != nil {
		return nil, errors.Wrap(err, `invalid signature`)
	}

	var token Token
	if err := json.Unmarshal(m.Payload(), &token); err != nil {
		return nil, errors.Wrap(err, `failed to parse token`)
	}
	return &token, nil
}

// New creates a new empty JWT token
func New() *Token {
	return &Token{
		privateClaims: make(map[string]interface{}),
	}
}

// Sign is a convenience function to create a signed JWT token serialized in
// compact form. `key` must match the key type required by the given
// signature method `method`
func (t *Token) Sign(method jwa.SignatureAlgorithm, key interface{}) ([]byte, error) {
	buf, err := json.Marshal(t)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal token`)
	}

	var hdr jws.StandardHeaders
	hdr.Set(`alg`, method.String())
	hdr.Set(`typ`, `JWT`)
	sign, err := jws.Sign(buf, method, key, jws.WithHeaders(&hdr))
	if err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}

	return sign, nil
}
