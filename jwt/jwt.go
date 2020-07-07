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
	"github.com/pkg/errors"
)

// ParseString calls Parse with the given string
func ParseString(s string, options ...Option) (Token, error) {
	return Parse(strings.NewReader(s), options...)
}

// ParseString calls Parse with the given byte sequence
func ParseBytes(s []byte, options ...Option) (Token, error) {
	return Parse(bytes.NewReader(s), options...)
}

// Parse parses the JWT token payload and creates a new `jwt.Token` object.
// The token must be encoded in either JSON format or compact format.
//
// If the token is signed and you want to verify the payload, you must
// pass the jwt.WithVerify(alg, key) or jwt.WithVerifyKeySet(jwk.Set) option.
// If you do not specify these parameters, no verification will be performed.
func Parse(src io.Reader, options ...Option) (Token, error) {
	var params VerifyParameters
	var keyset *jwk.Set
	for _, o := range options {
		switch o.Name() {
		case optkeyVerify:
			params = o.Value().(VerifyParameters)
		case optkeyKeySet:
			keyset = o.Value().(*jwk.Set)
		}
	}

	// We're going to need the raw bytes regardless. Read it.
	data, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, errors.Wrap(err, `failed to read from token data source`)
	}

	// If with matching kid is true, then look for the corresponding key in the
	// given key set, by matching the "kid" key
	if keyset != nil {
		alg, key, err := lookupMatchingKey(data, keyset)
		if err != nil {
			return nil, errors.Wrap(err, `failed to find matching key for verification`)
		}
		return parse(data, true, alg, key)
	}

	if params != nil {
		return parse(data, true, params.Algorithm(), params.Key())
	}

	return parse(data, false, "", nil)
}

// verify parameter exists to make sure that we don't accidentally skip
// over verification just because alg == ""  or key == nil or something.
func parse(data []byte, verify bool, alg jwa.SignatureAlgorithm, key interface{}) (Token, error) {
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

	token := New()
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
	data, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, errors.Wrap(err, `failed to read token from source`)
	}

	return parse(data, true, alg, key)
}

// Sign is a convenience function to create a signed JWT token serialized in
// compact form. `key` must match the key type required by the given
// signature method `method`
func Sign(t Token, method jwa.SignatureAlgorithm, key interface{}, options ...Option) ([]byte, error) {
	var hdr jws.Headers
	for _, o := range options {
		switch o.Name() {
		case optkeyHeaders:
			hdr = o.Value().(jws.Headers)
		}
	}

	buf, err := json.Marshal(t)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal token`)
	}

	if hdr == nil {
		hdr = jws.NewHeaders()
	}

	if err := hdr.Set(`alg`, method.String()); err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}
	if err := hdr.Set(`typ`, `JWT`); err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}
	sign, err := jws.Sign(buf, method, key, jws.WithHeaders(hdr))
	if err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}

	return sign, nil
}

// SignWithKey creates a singed JWT token which is singed by the given JWT key
func SignWithKey(t Token, key jwk.Key, options ...Option) ([]byte, error) {
	var hdr jws.Headers
	for _, o := range options {
		switch o.Name() {
		case optkeyHeaders:
			hdr = o.Value().(jws.Headers)
		}
	}
	if hdr == nil {
		hdr = jws.NewHeaders()
	}

	kid := key.KeyID()
	if kid != "" {
		if err := hdr.Set(jwk.KeyIDKey, kid); err != nil {
			return nil, errors.Wrap(err, `failed to sign payload`)
		}
	}

	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}

	return Sign(t, jwa.SignatureAlgorithm(key.Algorithm()), rawKey, WithHeaders(hdr))
}
