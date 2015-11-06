package jwa

// Signature algorithms
type SignatureAlgorithm string

const (
	NoSignature SignatureAlgorithm = "none"
	HS256                          = "HS256" // HMAC using SHA-256
	HS384                          = "HS384" // HMAC using SHA-384
	HS512                          = "HS512" // HMAC using SHA-512
	RS256                          = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384                          = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512                          = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	ES256                          = "ES256" // ECDSA using P-256 and SHA-256
	ES384                          = "ES384" // ECDSA using P-384 and SHA-384
	ES512                          = "ES512" // ECDSA using P-521 and SHA-512
	PS256                          = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384                          = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512                          = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
)

type KeyEncryptionAlgorithm string

const (
	RSA1_5             KeyEncryptionAlgorithm = "RSA1_5"             // RSA-PKCS1v1.5
	RSA_OAEP                                  = "RSA-OAEP"           // RSA-OAEP-SHA1
	RSA_OAEP_256                              = "RSA-OAEP-256"       // RSA-OAEP-SHA256
	A128KW                                    = "A128KW"             // AES key wrap (128)
	A192KW                                    = "A192KW"             // AES key wrap (192)
	A256KW                                    = "A256KW"             // AES key wrap (256)
	DIRECT                                    = "dir"                // Direct encryption
	ECDH_ES                                   = "ECDH-ES"            // ECDH-ES
	ECDH_ES_A128KW                            = "ECDH-ES+A128KW"     // ECDH-ES + AES key wrap (128)
	ECDH_ES_A192KW                            = "ECDH-ES+A192KW"     // ECDH-ES + AES key wrap (192)
	ECDH_ES_A256KW                            = "ECDH-ES+A256KW"     // ECDH-ES + AES key wrap (256)
	A128GCMKW                                 = "A128GCMKW"          // AES-GCM key wrap (128)
	A192GCMKW                                 = "A192GCMKW"          // AES-GCM key wrap (192)
	A256GCMKW                                 = "A256GCMKW"          // AES-GCM key wrap (256)
	PBES2_HS256_A128KW                        = "PBES2-HS256+A128KW" // PBES2 + HMAC-SHA256 + AES key wrap (128)
	PBES2_HS384_A192KW                        = "PBES2-HS384+A192KW" // PBES2 + HMAC-SHA384 + AES key wrap (192)
	PBES2_HS512_A256KW                        = "PBES2-HS512+A256KW" // PBES2 + HMAC-SHA512 + AES key wrap (256)
)

type ContentEncryptionAlgorithm string

const (
	A128CBC_HS256 ContentEncryptionAlgorithm = "A128CBC-HS256" // AES-CBC + HMAC-SHA256 (128)
	A192CBC_HS384                            = "A192CBC-HS384" // AES-CBC + HMAC-SHA384 (192)
	A256CBC_HS512                            = "A256CBC-HS512" // AES-CBC + HMAC-SHA512 (256)
	A128GCM                                  = "A128GCM"       // AES-GCM (128)
	A192GCM                                  = "A192GCM"       // AES-GCM (192)
	A256GCM                                  = "A256GCM"       // AES-GCM (256)
)

type CompressionAlgorithm string

const (
	NoCompression CompressionAlgorithm = ""    // No compression
	Deflate                            = "DEF" // DEFLATE (RFC 1951)
)
