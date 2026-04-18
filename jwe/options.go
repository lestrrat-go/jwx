package jwe

import (
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/option/v3"
)

type identCritExtension struct{}

// WithCritExtension declares that the caller understands and will process
// the named "crit" (Critical) header parameter extension(s) per RFC 7516
// Section 4.1.13 (which references RFC 7515 Section 4.1.11). The option
// is variadic and accumulating: a single call may register any number
// of extension names, and the option may be passed multiple times to add
// more.
//
// This option takes effect when jwe.WithCritValidation is enabled (the
// default in v4). With validation enabled, jwe.Decrypt() rejects any JWE
// whose protected header lists a "crit" extension that has not been
// declared via this option, satisfying the RFC's requirement that
// recipients MUST reject any "crit" extension they do not understand.
//
// IMPORTANT: declaring an extension here is a promise to the library
// that the caller knows what the extension means and will perform any
// validation, side effect, or policy enforcement the extension requires
// AFTER jwe.Decrypt() returns successfully. The library cannot inspect
// or enforce the semantics of an extension; it only checks that every
// "crit" entry in the message has been declared. If you register an
// extension and then forget to act on its value, you have effectively
// disabled the protection the producer was trying to obtain by listing
// the extension as critical.
//
// Concretely, the post-decrypt code path for a declared extension must:
//
//  1. Read the value of the named header from the decrypted message.
//  2. Apply whatever check or transformation the extension specifies
//     (e.g. for an "x-tenant-binding" extension, refuse to act on the
//     payload unless the binding matches the current tenant).
//  3. Treat any failure of that check as a decryption failure for
//     the application's purposes, even though jwe.Decrypt() returned
//     no error.
func WithCritExtension(names ...string) DecryptOption {
	return &decryptOption{option.New(identCritExtension{}, names)}
}

// WithProtectedHeaders is used to specify contents of the protected header.
// Some fields such as "enc" and "zip" will be overwritten when encryption is
// performed.
//
// There is no equivalent for unprotected headers in this implementation.
//
// This is a top-level `jwe.EncryptOption` passed directly to `jwe.Encrypt()`.
// A similarly named `jws.WithProtectedHeaders()` exists, but in `jws` it is a
// `WithKey` suboption passed inside `jws.WithKey(...)`. Do not confuse the
// two — the Go compiler will reject the wrong placement.
func WithProtectedHeaders(h Headers) EncryptOption {
	cloned, _ := h.Clone()
	return &encryptOption{option.New(identProtectedHeaders{}, cloned)}
}

type withKey struct {
	alg     jwa.KeyAlgorithm
	key     any
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

// WithPerRecipientHeaders is used to pass header values for each recipient.
// Note that these headers are by definition _unprotected_.
//
// The supplied Headers is cloned before being stored in the option, so the
// caller retains exclusive ownership of the original instance and the
// library never mutates or pools it.
func WithPerRecipientHeaders(hdr Headers) WithKeySuboption {
	if hdr != nil {
		if cloned, err := hdr.Clone(); err == nil {
			hdr = cloned
		}
	}
	return &withKeySuboption{option.New(identPerRecipientHeaders{}, hdr)}
}

// WithKey is used to pass a static algorithm/key pair to either `jwe.Encrypt()` or `jwe.Decrypt()`.
// Either a raw key or `jwk.Key` may be passed as `key`. If `key` is a `jwk.Key`,
// it must export to one of the raw key types described below.
//
// The `alg` parameter is the identifier for the key encryption algorithm that should be used.
// It is of type `jwa.KeyAlgorithm` but in reality you can only pass `jwa.KeyEncryptionAlgorithm`
// types. It is this way so that the value in `(jwk.Key).Algorithm()` can be directly
// passed to the option. If you specify other algorithm types such as `jwa.SignatureAlgorithm`,
// then you will get an error when `jwe.Encrypt()` or `jwe.Decrypt()` is executed.
//
// Built-in algorithm/key pairs are:
//
//   - `jwa.RSA1_5()` and `jwa.RSA_OAEP*()`: `*rsa.PublicKey` for `jwe.Encrypt()`
//     and the matching `*rsa.PrivateKey` for `jwe.Decrypt()`
//   - `jwa.A128KW()`, `jwa.A192KW()`, `jwa.A256KW()`, `jwa.A128GCMKW()`,
//     `jwa.A192GCMKW()`, and `jwa.A256GCMKW()`: shared symmetric key bytes of
//     the size required by the selected algorithm
//   - `jwa.DIRECT()`: shared symmetric key bytes used as the CEK. The key length
//     must match the selected `enc`, and DIRECT supports only a single recipient
//   - `jwa.ECDH_ES()` and `jwa.ECDH_ES_A*KW()`: recipient public key for
//     `jwe.Encrypt()` and the matching private key for `jwe.Decrypt()`. Built-in
//     support accepts `*ecdsa.PublicKey`, `*ecdsa.PrivateKey`,
//     `*ecdh.PublicKey`, and `*ecdh.PrivateKey`; `jwa.ECDH_ES()` also supports
//     only a single recipient. Custom raw key types may participate by
//     implementing the ECDH-ES interfaces in package
//     `github.com/lestrrat-go/jwx/v4/jwe/jwebb`
//   - `jwa.PBES2_*()`: password bytes
//   - `jwa.HPKE_*()`: recipient public key for `jwe.Encrypt()` and the matching
//     private key for `jwe.Decrypt()`. Built-in support accepts
//     `*ecdsa.PublicKey`, `*ecdsa.PrivateKey`, `*ecdh.PublicKey`, and
//     `*ecdh.PrivateKey` for the selected HPKE suite. Custom raw key types may
//     participate by implementing the HPKE interfaces in package
//     `github.com/lestrrat-go/jwx/v4/jwe/jwebb`
//
// `jwa.RSA1_5()` is supported only for interoperability with legacy peers.
// New applications should prefer an RSA-OAEP variant such as
// `jwa.RSA_OAEP_256()` because PKCS#1 v1.5 decryption is exposed to
// Bleichenbacher-style oracle attacks.
//
// Companion modules may register additional algorithm/key pairs. See the package
// README and companion-module documentation for extension-specific combinations
// such as ML-KEM.
//
// Unlike `jwe.WithKeySet()`, the `kid` field does not need to match for the key
// to be tried.
//
// # Suboptions
//
// `jwe.WithKey()` accepts the following suboption:
//
//   - `jwe.WithPerRecipientHeaders(Headers)`: per-recipient unprotected headers
//     for this recipient. These are distinct from the JWE protected headers that
//     apply to the whole message.
//
// Note that `jwe.WithProtectedHeaders()` is NOT a WithKey suboption — it is a
// top-level `jwe.EncryptOption` passed directly to `jwe.Encrypt()`. Users
// moving from `jws`, where `WithProtectedHeaders` is a `WithKey` suboption,
// should expect this shape difference. The Go compiler will reject the wrong
// placement because `jwe.WithKeySuboption` is a sealed interface distinct
// from `jwe.EncryptOption` (and distinct from `jws.WithKeySuboption`).
func WithKey(alg jwa.KeyAlgorithm, key any, options ...WithKeySuboption) EncryptDecryptOption {
	var hdr Headers
	for _, opt := range options {
		switch opt.Ident() {
		case identPerRecipientHeaders{}:
			hdr = option.MustGet[Headers](opt)
		}
	}

	return &encryptDecryptOption{option.New(identKey{}, &withKey{
		alg:     alg,
		key:     key,
		headers: hdr,
	})}
}

func WithKeySet(set jwk.Set, options ...WithKeySetSuboption) DecryptOption {
	requireKid := true
	for _, opt := range options {
		switch opt.Ident() {
		case identRequireKid{}:
			requireKid = option.MustGet[bool](opt)
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
	for _, opt := range options {
		switch opt.Ident() {
		case identPretty{}:
			pretty = option.MustGet[bool](opt)
		}
	}

	format := fmtJSON
	if pretty {
		format = fmtJSONPretty
	}
	return &encryptOption{option.New(identSerialization{}, format)}
}
