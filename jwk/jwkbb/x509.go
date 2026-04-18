package jwkbb

// Standard PEM block type strings. Use these with
// [RegisterX509Decoder] and in custom encoder implementations so the
// spelling stays consistent with what stdlib emits.
const (
	PrivateKeyBlockType    = `PRIVATE KEY`
	PublicKeyBlockType     = `PUBLIC KEY`
	ECPrivateKeyBlockType  = `EC PRIVATE KEY`
	RSAPublicKeyBlockType  = `RSA PUBLIC KEY`
	RSAPrivateKeyBlockType = `RSA PRIVATE KEY`
	CertificateBlockType   = `CERTIFICATE`
)
