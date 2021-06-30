package jwe

import (
	"context"

	"github.com/lestrrat-go/option"
)

type Option = option.Interface
type identMessage struct{}
type identPrettyFormat struct{}
type identProtectedHeader struct{}

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
