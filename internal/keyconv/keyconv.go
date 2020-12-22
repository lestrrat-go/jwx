package keyconv

import (
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/internal/blackmagic"
	"github.com/pkg/errors"
)

// RSAPrivateKey assigns src to dst, converting its type from a
// non-pointer to a pointer
func RSAPrivateKey(dst interface{}, src interface{}) error {
	var ptr *rsa.PrivateKey
	switch src := src.(type) {
	case rsa.PrivateKey:
		ptr = &src
	case *rsa.PrivateKey:
		ptr = src
	default:
		return errors.Errorf(`expected rsa.PrivateKey or *rsa.PrivateKey, got %T`, src)
	}
	return blackmagic.AssignIfCompatible(dst, ptr)
}

// RSAPublicKey assigns src to dst, converting its type from a
// non-pointer to a pointer
func RSAPublicKey(dst interface{}, src interface{}) error {
	var ptr *rsa.PublicKey
	switch src := src.(type) {
	case rsa.PublicKey:
		ptr = &src
	case *rsa.PublicKey:
		ptr = src
	default:
		return errors.Errorf(`expected rsa.PublicKey or *rsa.PublicKey, got %T`, src)
	}
	return blackmagic.AssignIfCompatible(dst, ptr)
}

// ECDSAPrivateKey assigns src to dst, converting its type from a
// non-pointer to a pointer
func ECDSAPrivateKey(dst interface{}, src interface{}) error {
	var ptr *ecdsa.PrivateKey
	switch src := src.(type) {
	case ecdsa.PrivateKey:
		ptr = &src
	case *ecdsa.PrivateKey:
		ptr = src
	default:
		return errors.Errorf(`expected ecdsa.PrivateKey or *ecdsa.PrivateKey, got %T`, src)
	}
	return blackmagic.AssignIfCompatible(dst, ptr)
}

// ECDSAPublicKey assigns src to dst, converting its type from a
// non-pointer to a pointer
func ECDSAPublicKey(dst interface{}, src interface{}) error {
	var ptr *ecdsa.PublicKey
	switch src := src.(type) {
	case ecdsa.PublicKey:
		ptr = &src
	case *ecdsa.PublicKey:
		ptr = src
	default:
		return errors.Errorf(`expected ecdsa.PublicKey or *ecdsa.PublicKey, got %T`, src)
	}
	return blackmagic.AssignIfCompatible(dst, ptr)
}
