// Package jwa defines the various algorithm described in https://tools.ietf.org/html/rfc7518
package jwa

// String returns the string representation of a KeyType
func (kty KeyType) String() string {
	return string(kty)
}

// String returns the string representation of a SignatureAlgorithm
func (alg SignatureAlgorithm) String() string {
	return string(alg)
}

// String returns the string representation of a KeyEncryptionAlgorithm
func (alg KeyEncryptionAlgorithm) String() string {
	return string(alg)
}

// String returns the string representation of a ContentEncryptionAlgorithm
func (alg ContentEncryptionAlgorithm) String() string {
	return string(alg)
}

// String returns the string representation of a CompressionAlgorithm
func (alg CompressionAlgorithm) String() string {
	return string(alg)
}

// String returns the string representation of a EllipticCurveAlgorithm
func (crv EllipticCurveAlgorithm) String() string {
	return string(crv)
}

// Size returns the size of the EllipticCurveAlgorithm
func (crv EllipticCurveAlgorithm) Size() int {
	switch crv {
	case P256:
		return 32
	case P384:
		return 48
	case P521:
		return 66
	}
	return 0
}
