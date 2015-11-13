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

func (crv EllipticCurveAlgorithm) String() string {
	return string(crv)
}

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
