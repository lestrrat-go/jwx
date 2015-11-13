// Package jwa defines the various algorithm described in https://tools.ietf.org/html/rfc7518
package jwa

func (kty KeyType) String() string {
	return string(kty)
}

func (alg SignatureAlgorithm) String() string {
	return string(alg)
}

func (alg KeyEncryptionAlgorithm) String() string {
	return string(alg)
}

func (alg ContentEncryptionAlgorithm) String() string {
	return string(alg)
}

func (alg CompressionAlgorithm) String() string {
	return string(alg)
}


