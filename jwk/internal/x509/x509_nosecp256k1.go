//go:build !jwx_es256k || !jwx_secp256k1_pem || !go1.20

package x509

import (
	"crypto/ecdsa"
	"crypto/x509"
)

func MarshalECPrivateKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(priv)
}

func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	return x509.ParseECPrivateKey(der)
}

func MarshalPKIXPublicKey(pub any) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

func ParsePKIXPublicKey(der []byte) (any, error) {
	return x509.ParsePKIXPublicKey(der)
}

func ParsePKCS8PrivateKey(der []byte) (interface{}, error) {
	return x509.ParsePKCS8PrivateKey(der)
}
