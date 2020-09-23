//go:generate go run internal/cmd/gentoken/main.go

// Package jwt implements JSON Web Tokens as described in https://tools.ietf.org/html/rfc7519
package jwt

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"github.com/pkg/errors"
)

type ParseOption func(*parseOptions)

type parseOptions struct {
	params VerifyParameters
	keyset *jwk.Set
	token  Token
}

type VerifyParameters interface {
	Algorithm() jwa.SignatureAlgorithm
	Key() interface{}
}

type verifyParams struct {
	alg jwa.SignatureAlgorithm
	key interface{}
}

func (p *verifyParams) Algorithm() jwa.SignatureAlgorithm {
	return p.alg
}

func (p *verifyParams) Key() interface{} {
	return p.key
}

// WithVerify forces the Parse method to verify the JWT message
// using the given key. XXX Should have been named something like
// WithVerificationKey
func WithVerify(alg jwa.SignatureAlgorithm, key interface{}) ParseOption {
	return func(po *parseOptions) {
		po.params = &verifyParams{
			alg: alg,
			key: key,
		}
	}
}

// WithKeySet forces the Parse method to verify the JWT message
// using one of the keys in the given key set. The key to be used
// is chosen by matching the Key ID of the JWT and the ID of the
// give keys.
func WithKeySet(set *jwk.Set) ParseOption {
	return func(po *parseOptions) {
		po.keyset = set
	}
}

// WithToken specifies the token instance that is used when parsing
// JWT tokens.
func WithToken(t Token) ParseOption {
	return func(po *parseOptions) {
		po.token = t
	}
}

// WithOpenIDClaims is passed to the various JWT parsing functions, and
// specifies that it should use an instance of `openid.Token` as the
// destination to store the parsed results.
//
// This is exactly equivalent to specifying `jwt.WithToken(openid.New())`
func WithOpenIDClaims() ParseOption {
	return WithToken(openid.New())
}

// ParseString calls Parse with the given string
func ParseString(s string, options ...ParseOption) (Token, error) {
	return Parse(strings.NewReader(s), options...)
}

// ParseString calls Parse with the given byte sequence
func ParseBytes(s []byte, options ...ParseOption) (Token, error) {
	return Parse(bytes.NewReader(s), options...)
}

// Parse parses the JWT token payload and creates a new `jwt.Token` object.
// The token must be encoded in either JSON format or compact format.
//
// If the token is signed and you want to verify the payload, you must
// pass the jwt.WithVerify(alg, key) or jwt.WithVerifyKeySet(jwk.Set) option.
// If you do not specify these parameters, no verification will be performed.
func Parse(src io.Reader, options ...ParseOption) (Token, error) {
	opts := parseOptions{}
	for _, o := range options {
		o(&opts)
	}

	// We're going to need the raw bytes regardless. Read it.
	data, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, errors.Wrap(err, `failed to read from token data source`)
	}

	// If with matching kid is true, then look for the corresponding key in the
	// given key set, by matching the "kid" key
	if opts.keyset != nil {
		alg, key, err := lookupMatchingKey(data, opts.keyset)
		if err != nil {
			return nil, errors.Wrap(err, `failed to find matching key for verification`)
		}
		return parse(opts.token, data, true, alg, key)
	}

	if opts.params != nil {
		return parse(opts.token, data, true, opts.params.Algorithm(), opts.params.Key())
	}

	return parse(opts.token, data, false, "", nil)
}

// verify parameter exists to make sure that we don't accidentally skip
// over verification just because alg == ""  or key == nil or something.
func parse(token Token, data []byte, verify bool, alg jwa.SignatureAlgorithm, key interface{}) (Token, error) {
	var payload []byte
	if verify {
		v, err := jws.Verify(data, alg, key)
		if err != nil {
			return nil, errors.Wrap(err, `failed to verify jws signature`)
		}
		payload = v
	} else {
		// TODO: seems slightly wasteful to use ioutil.ReadAll and then
		// create a new reader again. jws API kind of forces us to use
		// readers, but perhaps this can be fixed in future releases
		m, err := jws.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, errors.Wrap(err, `invalid jws message`)
		}
		payload = m.Payload()
	}

	if token == nil {
		token = New()
	}
	if err := json.Unmarshal(payload, token); err != nil {
		return nil, errors.Wrap(err, `failed to parse token`)
	}
	return token, nil
}

func lookupMatchingKey(data []byte, keyset *jwk.Set) (jwa.SignatureAlgorithm, interface{}, error) {
	msg, err := jws.Parse(bytes.NewReader(data))
	if err != nil {
		return "", nil, errors.Wrap(err, `failed to parse token data`)
	}

	headers := msg.Signatures()[0].ProtectedHeaders()
	kid := headers.KeyID()
	if kid == "" {
		return "", nil, errors.New(`failed to find matching key: no key ID specified in token`)
	}

	keys := keyset.LookupKeyID(kid)
	if len(keys) == 0 {
		return "", nil, errors.Errorf(`failed to find matching key for key ID %#v in key set`, kid)
	}

	var rawKey interface{}
	if err := keys[0].Raw(&rawKey); err != nil {
		return "", nil, errors.Wrapf(err, `failed to construct raw key from keyset (key ID=%#v)`, kid)
	}

	return headers.Algorithm(), rawKey, nil
}

// ParseVerify is marked to be deprecated. Please use jwt.Parse
// with appropriate options instead.
//
// ParseVerify a function that is similar to Parse(), but does not
// allow for parsing without signature verification parameters.
//
// If you want to provide a *jwk.Set and allow the library to automatically
// choose the key to use using the Key IDs, use the jwt.WithKeySet option
// along with the jwt.Parse function.
func ParseVerify(src io.Reader, alg jwa.SignatureAlgorithm, key interface{}) (Token, error) {
	return Parse(src, WithVerify(alg, key))
}

type SignOption func(*signOptions)

type signOptions struct {
	hdr jws.Headers
}

func WithHeaders(hdr jws.Headers) SignOption {
	return func(so *signOptions) {
		so.hdr = hdr
	}
}

// Sign is a convenience function to create a signed JWT token serialized in
// compact form.
//
// It accepts either a raw key (e.g. rsa.PrivateKey, ecdsa.PrivateKey, etc)
// or a jwk.Key, and the name of the algorithm that should be used to sign
// the token.
//
// If the key is a jwk.Key and the key contains a key ID (`kid` field),
// then it is added to the protected header generated by the signature
//
// The algorithm specified in the `alg` parameter must be able to support
// the type of key you provided, otherwise an error is returned.
//
// The protected header will also automatically have the `typ` field set
// to the literal value `JWT`.
func Sign(t Token, alg jwa.SignatureAlgorithm, key interface{}, options ...SignOption) ([]byte, error) {
	opts := signOptions{}
	for _, o := range options {
		o(&opts)
	}

	buf, err := json.Marshal(t)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal token`)
	}

	if opts.hdr == nil {
		opts.hdr = jws.NewHeaders()
	}

	if err := opts.hdr.Set(`typ`, `JWT`); err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}
	sign, err := jws.Sign(buf, alg, key, jws.WithHeaders(opts.hdr))
	if err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}

	return sign, nil
}
