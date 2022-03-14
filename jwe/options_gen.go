// This file is auto-generated by internal/cmd/genoptions/main.go. DO NOT EDIT

package jwe

import (
	"io/fs"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/option"
)

type Option = option.Interface

// CompactOption describes options that can be passed to `jwe.Compact`
type CompactOption interface {
	Option
	compactOption()
}

type compactOption struct {
	Option
}

func (*compactOption) compactOption() {}

// DecryptOption describes options that can be passed to `jwe.Decrypt`
type DecryptOption interface {
	Option
	decryptOption()
}

type decryptOption struct {
	Option
}

func (*decryptOption) decryptOption() {}

// EncryptDecryptOption describes options that can be passed to either `jwe.Encrypt` or `jwe.Decrypt`
type EncryptDecryptOption interface {
	Option
	encryptOption()
	decryptOption()
}

type encryptDecryptOption struct {
	Option
}

func (*encryptDecryptOption) encryptOption() {}

func (*encryptDecryptOption) decryptOption() {}

// EncryptOption describes options that can be passed to `jwe.Encrypt`
type EncryptOption interface {
	Option
	encryptOption()
}

type encryptOption struct {
	Option
}

func (*encryptOption) encryptOption() {}

// ReadFileOption is a type of `Option` that can be passed to `jwe.Parse`
type ParseOption interface {
	Option
	readFileOption()
}

type parseOption struct {
	Option
}

func (*parseOption) readFileOption() {}

// ReadFileOption is a type of `Option` that can be passed to `jwe.ReadFile`
type ReadFileOption interface {
	Option
	readFileOption()
}

type readFileOption struct {
	Option
}

func (*readFileOption) readFileOption() {}

// JSONSuboption describes suboptions that can be passed to `jwe.WithJSON()` option
type WithJSONSuboption interface {
	Option
	withJSONSuboption()
}

type withJSONSuboption struct {
	Option
}

func (*withJSONSuboption) withJSONSuboption() {}

// WithKeySetSuboption is a suboption passed to the WithKeySet() option
type WithKeySetSuboption interface {
	Option
	withKeySetSuboption()
}

type withKeySetSuboption struct {
	Option
}

func (*withKeySetSuboption) withKeySetSuboption() {}

type identCompress struct{}
type identContentEncryptionAlgorithm struct{}
type identFS struct{}
type identKey struct{}
type identKeyProvider struct{}
type identMergeProtectedHeaders struct{}
type identMessage struct{}
type identPerRecipientHeaders struct{}
type identPretty struct{}
type identProtectedHeaders struct{}
type identRequireKid struct{}
type identSerialization struct{}

func (identCompress) String() string {
	return "WithCompress"
}

func (identContentEncryptionAlgorithm) String() string {
	return "WithContentEncryption"
}

func (identFS) String() string {
	return "WithFS"
}

func (identKey) String() string {
	return "WithKey"
}

func (identKeyProvider) String() string {
	return "WithKeyProvider"
}

func (identMergeProtectedHeaders) String() string {
	return "WithMergeProtectedHeaders"
}

func (identMessage) String() string {
	return "WithMessage"
}

func (identPerRecipientHeaders) String() string {
	return "WithPerRecipientHeaders"
}

func (identPretty) String() string {
	return "WithPretty"
}

func (identProtectedHeaders) String() string {
	return "WithProtectedHeaders"
}

func (identRequireKid) String() string {
	return "WithRequireKid"
}

func (identSerialization) String() string {
	return "WithCompact"
}

// WithCompress specifies the compression algorithm to use when encrypting
// a payload using `jwe.Encrypt` (Yes, we know it can only be "" or "DEF",
// but the way the specification is written it could allow for more options,
// and therefore this option takes an argument)
func WithCompress(v jwa.CompressionAlgorithm) EncryptOption {
	return &encryptOption{option.New(identCompress{}, v)}
}

// WithContentEncryptionAlgorithm specifies the algorithm to encrypt the
// JWE message content with. If not provided, `jwa.A256GCM` is used.
func WithContentEncryption(v jwa.ContentEncryptionAlgorithm) EncryptOption {
	return &encryptOption{option.New(identContentEncryptionAlgorithm{}, v)}
}

// WithFS specifies the source `fs.FS` object to read the file from.
func WithFS(v fs.FS) ReadFileOption {
	return &readFileOption{option.New(identFS{}, v)}
}

func WithKeyProvider(v KeyProvider) DecryptOption {
	return &decryptOption{option.New(identKeyProvider{}, v)}
}

// WithMergeProtectedHeaders specify that when given multiple headers
// as options to `jwe.Encrypt`, these headers should be merged instead
// of overwritten
func WithMergeProtectedHeaders(v bool) EncryptOption {
	return &encryptOption{option.New(identMergeProtectedHeaders{}, v)}
}

// WithMessage provides a message object to be populated by `jwe.Decrpt`
// Using this option allows you to decrypt AND obtain the `jwe.Message`
// in one go.
//
// Note that you should NOT be using the message object for anything other
// than inspecting its contents. Particularly, do not expect the message
// reliable when you call `Decrypt` on it. `(jwe.Message).Decrypt` is
// slated to be deprecated in the next major version.
func WithMessage(v *Message) DecryptOption {
	return &decryptOption{option.New(identMessage{}, v)}
}

// WithPretty specifies whether the JSON output should be formatted and
// indented
func WithPretty(v bool) WithJSONSuboption {
	return &withJSONSuboption{option.New(identPretty{}, v)}
}

// WithrequiredKid specifies whether the keys in the jwk.Set should
// only be matched if the target JWE message's Key ID and the Key ID
// in the given key matches.
func WithRequireKid(v bool) WithKeySetSuboption {
	return &withKeySetSuboption{option.New(identRequireKid{}, v)}
}

// WithCompact specifies that the result of `jwe.Encrypt()` is serialized in
// compact format.
//
// By default `jwe.Encrypt()` will opt to use compact format, so you usually
// do not need to specify this option other than to be explicit about it
func WithCompact() EncryptOption {
	return &encryptOption{option.New(identSerialization{}, fmtCompact)}
}
