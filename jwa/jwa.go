//go:generate ../tools/cmd/genjwa.sh

// Package jwa defines the various algorithm described in https://tools.ietf.org/html/rfc7518
package jwa

import "fmt"

// KeyAlgorithm is a workaround for jwk.Key being able to contain different
// types of algorithms in its `alg` field.
//
// Previously the storage for the `alg` field was represented as a string,
// but this caused some users to wonder why the field was not typed appropriately
// like other fields.
//
// Ideally we would like to keep track of Signature Algorithms and
// Content Encryption Algorithms separately, and force the APIs to
// type-check at compile time, but this allows users to pass a value from a
// jwk.Key directly
type KeyAlgorithm interface {
	String() string
}

// UnknownKeyAlgorithm represents an algorithm that the library is not aware of.
type UnknownKeyAlgorithm string

func (s UnknownKeyAlgorithm) String() string {
	return string(s)
}

func (UnknownKeyAlgorithm) AcceptValue(_ interface{}) error {
	return fmt.Errorf(`jwa.UnknownKeyAlgorithm does not support Accept() method calls`)
}

// KeyAlgorithmFrom takes either a string, `jwa.SignatureAlgorithm` or `jwa.KeyEncryptionAlgorithm`
// and returns a `jwa.KeyAlgorithm`.
//
// If the value cannot be handled, it returns an `jwa.UnknownKeyAlgorithm`
// object instead of returning an error. This design choice was made to allow
// users to directly pass the return value to functions such as `jws.Sign()`
func KeyAlgorithmFrom(v interface{}) (KeyAlgorithm, error) {
	switch v := v.(type) {
	case SignatureAlgorithm:
		return v, nil
	case KeyEncryptionAlgorithm:
		return v, nil
	case ContentEncryptionAlgorithm:
		return v, nil
	case string:
		var salg SignatureAlgorithm
		if err := salg.Accept(v); err == nil {
			return salg, nil
		}

		var kealg KeyEncryptionAlgorithm
		if err := kealg.Accept(v); err == nil {
			return kealg, nil
		}

		var ctealg ContentEncryptionAlgorithm
		if err := ctealg.Accept(v); err == nil {
			return ctealg, nil
		}

		return UnknownKeyAlgorithm(v), nil
	default:
		return UnknownKeyAlgorithm(fmt.Sprintf("%s", v)), fmt.Errorf(`failed to accept variable of type %T as a key algorithm`, v)
	}
}
