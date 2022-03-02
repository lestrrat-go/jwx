package jwe

import (
	"context"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/option"
)

// Specify contents of the protected header. Some fields such as
// "enc" and "zip" will be overwritten when encryption is performed.
func WithProtectedHeaders(h Headers) EncryptOption {
	cloned, _ := h.Clone(context.Background())
	return &encryptOption{option.New(identProtectedHeaders{}, cloned)}
}

type DecryptEncryptOption interface {
	DecryptOption
	EncryptOption
}

type decryptEncryptOption struct {
	Option
}

func (*decryptEncryptOption) decryptOption() {}
func (*decryptEncryptOption) encryptOption() {}

type withKey struct {
	alg     jwa.KeyAlgorithm
	key     interface{}
	headers Headers
}

type WithKeySuboption interface {
	Option
	withKeySuboption()
}

type withKeySuboption struct {
	Option
}

func (*withKeySuboption) withKeySuboption() {}

func WithRecipientHeaders(hdr Headers) WithKeySuboption {
	return &withKeySuboption{option.New(identRecipientHeaders{}, hdr)}
}

func WithKey(alg jwa.KeyAlgorithm, key interface{}, options ...WithKeySuboption) DecryptEncryptOption {
	var hdr Headers
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identRecipientHeaders{}:
			hdr = option.Value().(Headers)
		}
	}

	return &decryptEncryptOption{option.New(identKey{}, &withKey{
		alg:     alg,
		key:     key,
		headers: hdr,
	})}
}

func WithKeySet(set jwk.Set, options ...WithKeySetSuboption) DecryptOption {
	var requireKid bool
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identRequireKid{}:
			requireKid = option.Value().(bool)
		}
	}

	return WithKeyProvider(&keySetProvider{
		set:        set,
		requireKid: requireKid,
	})
}

// WithJSON specifies that the result of `jwe.Encrypt()` is serialized in
// JSON format.
//
// If you pass multiple keys to `jwe.Encrypt()`, it will fail unless
// you also pass this option.
func WithJSON(options ...WithJSONSuboption) EncryptOption {
	var pretty bool
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identPretty{}:
			pretty = option.Value().(bool)
		}
	}

	format := fmtJSON
	if pretty {
		format = fmtJSONPretty
	}
	return &encryptOption{option.New(identSerialization{}, format)}
}
