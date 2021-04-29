//go:generate go run internal/cmd/gentoken/main.go

// Package jwt implements JSON Web Tokens as described in https://tools.ietf.org/html/rfc7519
package jwt

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/internal/json"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

// Settings controls global settings that are specific to JWTs.
func Settings(options ...GlobalOption) {
	var flattenAudienceBool bool

	//nolint:forcetypeassert
	for _, option := range options {
		switch option.Ident() {
		case identFlattenAudience{}:
			flattenAudienceBool = option.Value().(bool)
		}
	}

	v := atomic.LoadUint32(&json.FlattenAudience)
	if (v == 1) != flattenAudienceBool {
		var newVal uint32
		if flattenAudienceBool {
			newVal = 1
		}
		atomic.CompareAndSwapUint32(&json.FlattenAudience, v, newVal)
	}
}

var registry = json.NewRegistry()

// ParseString calls Parse against a string
func ParseString(s string, options ...ParseOption) (Token, error) {
	return parseBytes([]byte(s), options...)
}

// Parse parses the JWT token payload and creates a new `jwt.Token` object.
// The token must be encoded in either JSON format or compact format.
//
// If the token is signed and you want to verify the payload matches the signature,
// you must pass the jwt.WithVerify(alg, key) or jwt.WithKeySet(jwk.Set) option.
// If you do not specify these parameters, no verification will be performed.
//
// If you also want to assert the validity of the JWT itself (i.e. expiration
// and such), use the `Validate()` function on the returned token, or pass the
// `WithValidate(true)` option. Validate options can also be passed to
// `Parse`
//
// This function takes both ParseOption and ValidateOption types:
// ParseOptions control the parsing behavior, and ValidateOptions are
// passed to `Validate()` when `jwt.WithValidate` is specified.
func Parse(s []byte, options ...ParseOption) (Token, error) {
	return parseBytes(s, options...)
}

// ParseReader calls Parse against an io.Reader
func ParseReader(src io.Reader, options ...ParseOption) (Token, error) {
	// We're going to need the raw bytes regardless. Read it.
	data, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, errors.Wrap(err, `failed to read from token data source`)
	}
	return parseBytes(data, options...)
}

func parseBytes(data []byte, options ...ParseOption) (Token, error) {
	var params VerifyParameters
	var keyset jwk.Set
	var useDefault bool
	var token Token
	var validate bool
	var ok bool
	for _, o := range options {
		//nolint:forcetypeassert
		switch o.Ident() {
		case identVerify{}:
			params = o.Value().(VerifyParameters)
		case identKeySet{}:
			keyset, ok = o.Value().(jwk.Set)
			if !ok {
				return nil, errors.Errorf(`invalid JWK set passed via WithKeySet() option (%T)`, o.Value())
			}
		case identToken{}:
			token, ok = o.Value().(Token)
			if !ok {
				return nil, errors.Errorf(`invalid token passed via WithToken() option (%T)`, o.Value())
			}
		case identDefault{}:
			useDefault = o.Value().(bool)
		case identValidate{}:
			validate = o.Value().(bool)
		}
	}

	data = bytes.TrimSpace(data)

	// If with matching kid is true, then look for the corresponding key in the
	// given key set, by matching the "kid" key
	if keyset != nil {
		alg, key, err := lookupMatchingKey(data, keyset, useDefault)
		if err != nil {
			return nil, errors.Wrap(err, `failed to find matching key for verification`)
		}
		return parse(token, data, true, alg, key, validate, options...)
	}

	if params != nil {
		return parse(token, data, true, params.Algorithm(), params.Key(), validate, options...)
	}

	return parse(token, data, false, "", nil, validate, options...)
}

// verify parameter exists to make sure that we don't accidentally skip
// over verification just because alg == ""  or key == nil or something.
func parse(token Token, data []byte, verify bool, alg jwa.SignatureAlgorithm, key interface{}, validate bool, options ...ParseOption) (Token, error) {
	var payload []byte
	if verify {
		// If verify is true, the data MUST be a valid jws message
		v, err := jws.Verify(data, alg, key)
		if err != nil {
			return nil, errors.Wrap(err, `failed to verify jws signature`)
		}
		payload = v
	} else {
		// 1. eyXXX.XXXX.XXXX
		// 2. { "signatures": [ ... ] }
		// 3. { "foo": "bar" }
		if len(data) > 0 && data[0] == '{' {
			m, err := jws.Parse(data)
			if err == nil {
				payload = m.Payload()
			} else {
				// It's JSON, but we don't have proper JWS fields.
				payload = data
			}
		} else {
			// Probably compact JWS
			m, err := jws.Parse(data)
			if err != nil {
				return nil, errors.Wrap(err, `invalid jws message`)
			}
			payload = m.Payload()
		}
	}

	if token == nil {
		token = New()
	}
	if err := json.Unmarshal(payload, token); err != nil {
		return nil, errors.Wrap(err, `failed to parse token`)
	}

	if validate {
		var vopts []ValidateOption
		for _, o := range options {
			if v, ok := o.(ValidateOption); ok {
				vopts = append(vopts, v)
			}
		}

		if err := Validate(token, vopts...); err != nil {
			return nil, err
		}
	}
	return token, nil
}

func lookupMatchingKey(data []byte, keyset jwk.Set, useDefault bool) (jwa.SignatureAlgorithm, interface{}, error) {
	msg, err := jws.Parse(data)
	if err != nil {
		return "", nil, errors.Wrap(err, `failed to parse token data`)
	}

	headers := msg.Signatures()[0].ProtectedHeaders()
	kid := headers.KeyID()
	if kid == "" {
		if !useDefault {
			return "", nil, errors.New(`failed to find matching key: no key ID specified in token`)
		} else if useDefault && keyset.Len() > 1 {
			return "", nil, errors.New(`failed to find matching key: no key ID specified in token but multiple in key set`)
		}
	}

	var key jwk.Key
	var ok bool
	if kid == "" {
		key, ok = keyset.Get(0)
		if !ok {
			return "", nil, errors.New(`empty keyset`)
		}
	} else {
		key, ok = keyset.LookupKeyID(kid)
		if !ok {
			return "", nil, errors.Errorf(`failed to find matching key for key ID %#v in key set`, kid)
		}
	}

	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return "", nil, errors.Wrapf(err, `failed to construct raw key from keyset (key ID=%#v)`, kid)
	}

	var alg jwa.SignatureAlgorithm
	if err := alg.Accept(key.Algorithm()); err != nil {
		return "", nil, errors.Wrapf(err, `invalid signatre algorithm %s`, key.Algorithm())
	}

	return alg, rawKey, nil
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
// to the literal value `JWT`, unless you provide a custom value for it
// by jwt.WithHeaders option.
func Sign(t Token, alg jwa.SignatureAlgorithm, key interface{}, options ...Option) ([]byte, error) {
	var hdr jws.Headers
	for _, o := range options {
		//nolint:forcetypeassert
		switch o.Ident() {
		case identHeaders{}:
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

	if _, ok := hdr.Get(`typ`); !ok {
		if err := hdr.Set(`typ`, `JWT`); err != nil {
			return nil, errors.Wrap(err, `failed to set typ field`)
		}
	}

	sign, err := jws.Sign(buf, alg, key, jws.WithHeaders(hdr))
	if err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}

	return sign, nil
}

// Equal compares two JWT tokens. Do not use `reflect.Equal` or the like
// to compare tokens as they will also compare extra detail such as
// sync.Mutex objects used to control concurrent access.
//
// The comparison for values is currently done using a simple equality ("=="),
// except for time.Time, which uses time.Equal after dropping the monotonic
// clock and truncating the values to 1 second accuracy.
//
// if both t1 and t2 are nil, returns true
func Equal(t1, t2 Token) bool {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if t1 == nil && t2 == nil {
		return true
	}

	// we already checked for t1 == t2 == nil, so safe to do this
	if t1 == nil || t2 == nil {
		return false
	}

	m1, err := t1.AsMap(ctx)
	if err != nil {
		return false
	}

	for iter := t2.Iterate(ctx); iter.Next(ctx); {
		pair := iter.Pair()

		v1 := m1[pair.Key.(string)]
		v2 := pair.Value
		switch tmp := v1.(type) {
		case time.Time:
			tmp2, ok := v2.(time.Time)
			if !ok {
				return false
			}
			tmp = tmp.Round(0).Truncate(time.Second)
			tmp2 = tmp2.Round(0).Truncate(time.Second)
			if !tmp.Equal(tmp2) {
				return false
			}
		default:
			if v1 != v2 {
				return false
			}
		}
		delete(m1, pair.Key.(string))
	}

	return len(m1) == 0
}

func (t *stdToken) Clone() (Token, error) {
	dst := New()

	ctx := context.Background()
	for iter := t.Iterate(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		if err := dst.Set(pair.Key.(string), pair.Value); err != nil {
			return nil, errors.Wrapf(err, `failed to set %s`, pair.Key.(string))
		}
	}
	return dst, nil
}

// RegisterCustomField allows users to specify that a private field
// be decoded as an instance of the specified type. This option has
// a global effect.
//
// For example, suppose you have a custom field `x-birthday`, which
// you want to represent as a string formatted in RFC3339 in JSON,
// but want it back as `time.Time`.
//
// In that case you would register a custom field as follows
//
//   jwt.RegisterCustomField(`x-birthday`, timeT)
//
// Then `token.Get("x-birthday")` will still return an `interface{}`,
// but you can convert its type to `time.Time`
//
//   bdayif, _ := token.Get(`x-birthday`)
//   bday := bdayif.(time.Time)
//
func RegisterCustomField(name string, object interface{}) {
	registry.Register(name, object)
}
