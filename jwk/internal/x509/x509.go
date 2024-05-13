package x509

import (
	"crypto/rsa"
	"crypto/x509"
)

// In this x509 package we provide a proxy for crypto/x509 methods,
// so that we can easily swap out the ParseECPrivateKey method with
// our version of it that recognizes the secp256k1 curve...
// _IF_ the jwx_es256k build tag is set.

func MarshalPKCS1PrivateKey(priv *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(priv)
}

func MarshalPKCS8PrivateKey(priv interface{}) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(priv)
}

func ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(der)
}

func ParsePKCS1PublicKey(der []byte) (*rsa.PublicKey, error) {
	return x509.ParsePKCS1PublicKey(der)
}

func ParseCertificate(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}
