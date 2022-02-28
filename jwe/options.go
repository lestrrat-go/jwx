package jwe

import (
	"context"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/option"
)

type Option = option.Interface
type identMessage struct{}
type identPostParser struct{}
type identPrettyFormat struct{}
type identProtectedHeader struct{}
type identRecipientHeaders struct{}
type identKey struct{}
type identCompress struct{}
type identContentEncryptionAlgorithm struct{}

type DecryptOption interface {
	Option
	decryptOption()
}

type decryptOption struct {
	Option
}

func (*decryptOption) decryptOption() {}

type SerializerOption interface {
	Option
	serializerOption()
}

type serializerOption struct {
	Option
}

func (*serializerOption) serializerOption() {}

type EncryptOption interface {
	Option
	encryptOption()
}

type encryptOption struct {
	Option
}

func (*encryptOption) encryptOption() {}

// WithPrettyFormat specifies if the `jwe.JSON` serialization tool
// should generate pretty-formatted output
func WithPrettyFormat(b bool) SerializerOption {
	return &serializerOption{option.New(identPrettyFormat{}, b)}
}

// Specify contents of the protected header. Some fields such as
// "enc" and "zip" will be overwritten when encryption is performed.
func WithProtectedHeaders(h Headers) EncryptOption {
	cloned, _ := h.Clone(context.Background())
	return &encryptOption{option.New(identProtectedHeader{}, cloned)}
}

// WithMessage provides a message object to be populated by `jwe.Decrpt`
// Using this option allows you to decrypt AND obtain the `jwe.Message`
// in one go.
//
// Note that you should NOT be using the message object for anything other
// than inspecting its contents. Particularly, do not expect the message
// reliable when you call `Decrypt` on it. `(jwe.Message).Decrypt` is
// slated to be deprecated in the next major version.
func WithMessage(m *Message) DecryptOption {
	return &decryptOption{option.New(identMessage{}, m)}
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

// Because there _could_ be other values to the compress algorithm,
// we take an argument
func WithCompress(alg jwa.CompressionAlgorithm) EncryptOption {
	return &encryptOption{option.New(identCompress{}, alg)}
}

func WithContentEncryption(alg jwa.ContentEncryptionAlgorithm) EncryptOption {
	return &encryptOption{option.New(identContentEncryptionAlgorithm{}, alg)}
}
