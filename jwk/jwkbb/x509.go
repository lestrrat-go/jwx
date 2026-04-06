package jwkbb

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	PrivateKeyBlockType    = `PRIVATE KEY`
	PublicKeyBlockType     = `PUBLIC KEY`
	ECPrivateKeyBlockType  = `EC PRIVATE KEY`
	RSAPublicKeyBlockType  = `RSA PUBLIC KEY`
	RSAPrivateKeyBlockType = `RSA PRIVATE KEY`
	CertificateBlockType   = `CERTIFICATE`
)

// EncodeX509 encodes the given value into ASN.1 DER format, and returns
// the encoded bytes. The value must be one of the following types:
// *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey,
// *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey.
//
// Users can pass a pre-allocated byte slice (but make sure its length is
// changed so that the encoded buffer is appended to the correct location)
// as `dst` to avoid allocations.
func EncodeX509(dst []byte, v any) ([]byte, error) {
	var block pem.Block
	// Try to convert it into a certificate
	switch v := v.(type) {
	case *rsa.PrivateKey:
		block.Type = RSAPrivateKeyBlockType
		block.Bytes = x509.MarshalPKCS1PrivateKey(v)
	case *ecdsa.PrivateKey:
		marshaled, err := x509.MarshalECPrivateKey(v)
		if err != nil {
			return nil, err
		}
		block.Type = ECPrivateKeyBlockType
		block.Bytes = marshaled
	case ed25519.PrivateKey:
		marshaled, err := x509.MarshalPKCS8PrivateKey(v)
		if err != nil {
			return nil, err
		}
		block.Type = PrivateKeyBlockType
		block.Bytes = marshaled
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		marshaled, err := x509.MarshalPKIXPublicKey(v)
		if err != nil {
			return nil, err
		}
		block.Type = PublicKeyBlockType
		block.Bytes = marshaled
	default:
		return nil, fmt.Errorf(`unsupported type %T for ASN.1 DER encoding`, v)
	}

	encoded := pem.EncodeToMemory(&block)
	dst = append(dst, encoded...)
	return dst, nil
}

func DecodeX509(block *pem.Block) (any, error) {
	switch block.Type {
	case RSAPrivateKeyBlockType:
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case RSAPublicKeyBlockType:
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case ECPrivateKeyBlockType:
		return x509.ParseECPrivateKey(block.Bytes)
	case PublicKeyBlockType:
		return x509.ParsePKIXPublicKey(block.Bytes)
	case PrivateKeyBlockType:
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case CertificateBlockType:
		// Only the public key is extracted. Certificate validation (chain,
		// expiration, CN/SAN, EKU, etc.) is intentionally not performed here;
		// it is an application-level concern. See jwk.ParseKey documentation.
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf(`failed to parse certificate: %w`, err)
		}
		return cert.PublicKey, nil
	default:
		return nil, fmt.Errorf(`invalid PEM block type %s`, block.Type)
	}
}
