package jwe

import (
	"context"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/option"
)

type SerializerOption interface {
	Option
	serializerOption()
}

type serializerOption struct {
	Option
}

func (*serializerOption) serializerOption() {}

// WithPrettyFormat specifies if the `jwe.JSON` serialization tool
// should generate pretty-formatted output
func WithPrettyFormat(b bool) SerializerOption {
	return &serializerOption{option.New(identPrettyFormat{}, b)}
}

// Specify contents of the protected header. Some fields such as
// "enc" and "zip" will be overwritten when encryption is performed.
func WithProtectedHeaders(h Headers) EncryptOption {
	cloned, _ := h.Clone(context.Background())
	return &encryptOption{option.New(identProtectedHeaders{}, cloned)}
}

// WithPostParser specifies the handler to be called immediately
// after the JWE message has been parsed, but before decryption
// takes place during `jwe.Decrypt`.
//
// This option exists to allow advanced users that require the use
// of information stored in the JWE message to determine how the
// decryption should be handled.
//
// For security reasons it is highly recommended that you thoroughly
// study how the process works before using this option. This is especially
// true if you are trying to infer key algorithms and keys to use to
// decrypt a message using non-standard hints.
func WithPostParser(p PostParser) DecryptOption {
	return &decryptOption{option.New(identPostParser{}, p)}
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

type JSONSuboption interface {
	Option
	withJSONSuboption()
}

type jsonSuboption struct {
	Option
}

func (*jsonSuboption) withJSONSuboption() {}

func WithPretty(v bool) JSONSuboption {
	return &jsonSuboption{option.New(identPretty{}, v)}
}

// WithJSON specifies that the result of `jwe.Encrypt()` is serialized in
// JSON format.
//
// If you pass multiple keys to `jwe.Encrypt()`, it will fail unless
// you also pass this option.
func WithJSON(options ...JSONSuboption) EncryptOption {
	var pretty bool
	for _, option := range options {
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
