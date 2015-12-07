package jwa

// KeyType represents the key type ("kty") that are supported
type KeyType string

// Supported KeyTypes
const (
	EC       KeyType = "EC"  // Elliptic Curve
	RSA      KeyType = "RSA" // RSA
	OctetSeq KeyType = "oct" // Octet sequence (used to represent symmetric keys)
)

// EllipticCurveAlgorithm represents the algorithms used for EC keys
type EllipticCurveAlgorithm string

// Supported EllipticCurveAlgorithms
const (
	P256 EllipticCurveAlgorithm = "P-256"
	P384 EllipticCurveAlgorithm = "P-384"
	P521 EllipticCurveAlgorithm = "P-521"
)

// SignatureAlgorithm represents the various signature algorithms
// as described in https://tools.ietf.org/html/rfc7518#section-3.1
type SignatureAlgorithm string

// Supported SignatureAlgorithms
const (
	NoSignature SignatureAlgorithm = "none"
	HS256       SignatureAlgorithm = "HS256" // HMAC using SHA-256
	HS384       SignatureAlgorithm = "HS384" // HMAC using SHA-384
	HS512       SignatureAlgorithm = "HS512" // HMAC using SHA-512
	RS256       SignatureAlgorithm = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384       SignatureAlgorithm = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512       SignatureAlgorithm = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	ES256       SignatureAlgorithm = "ES256" // ECDSA using P-256 and SHA-256
	ES384       SignatureAlgorithm = "ES384" // ECDSA using P-384 and SHA-384
	ES512       SignatureAlgorithm = "ES512" // ECDSA using P-521 and SHA-512
	PS256       SignatureAlgorithm = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384       SignatureAlgorithm = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512       SignatureAlgorithm = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
)

// KeyEncryptionAlgorithm represents the various encryption
// algorithms as described in https://tools.ietf.org/html/rfc7518#section-4.1
type KeyEncryptionAlgorithm string

// Supported KeyEncryptionAlgorithms
const (
	RSA1_5             KeyEncryptionAlgorithm = "RSA1_5"             // RSA-PKCS1v1.5
	RSA_OAEP           KeyEncryptionAlgorithm = "RSA-OAEP"           // RSA-OAEP-SHA1
	RSA_OAEP_256       KeyEncryptionAlgorithm = "RSA-OAEP-256"       // RSA-OAEP-SHA256
	A128KW             KeyEncryptionAlgorithm = "A128KW"             // AES key wrap (128)
	A192KW             KeyEncryptionAlgorithm = "A192KW"             // AES key wrap (192)
	A256KW             KeyEncryptionAlgorithm = "A256KW"             // AES key wrap (256)
	DIRECT             KeyEncryptionAlgorithm = "dir"                // Direct encryption
	ECDH_ES            KeyEncryptionAlgorithm = "ECDH-ES"            // ECDH-ES
	ECDH_ES_A128KW     KeyEncryptionAlgorithm = "ECDH-ES+A128KW"     // ECDH-ES + AES key wrap (128)
	ECDH_ES_A192KW     KeyEncryptionAlgorithm = "ECDH-ES+A192KW"     // ECDH-ES + AES key wrap (192)
	ECDH_ES_A256KW     KeyEncryptionAlgorithm = "ECDH-ES+A256KW"     // ECDH-ES + AES key wrap (256)
	A128GCMKW          KeyEncryptionAlgorithm = "A128GCMKW"          // AES-GCM key wrap (128)
	A192GCMKW          KeyEncryptionAlgorithm = "A192GCMKW"          // AES-GCM key wrap (192)
	A256GCMKW          KeyEncryptionAlgorithm = "A256GCMKW"          // AES-GCM key wrap (256)
	PBES2_HS256_A128KW KeyEncryptionAlgorithm = "PBES2-HS256+A128KW" // PBES2 + HMAC-SHA256 + AES key wrap (128)
	PBES2_HS384_A192KW KeyEncryptionAlgorithm = "PBES2-HS384+A192KW" // PBES2 + HMAC-SHA384 + AES key wrap (192)
	PBES2_HS512_A256KW KeyEncryptionAlgorithm = "PBES2-HS512+A256KW" // PBES2 + HMAC-SHA512 + AES key wrap (256)
)

// ContentEncryptionAlgorithm represents the various encryption
// algorithms as described in https://tools.ietf.org/html/rfc7518#section-5
type ContentEncryptionAlgorithm string

// Supported ContentEncryptionAlgorithms
const (
	A128CBC_HS256 ContentEncryptionAlgorithm = "A128CBC-HS256" // AES-CBC + HMAC-SHA256 (128)
	A192CBC_HS384 ContentEncryptionAlgorithm = "A192CBC-HS384" // AES-CBC + HMAC-SHA384 (192)
	A256CBC_HS512 ContentEncryptionAlgorithm = "A256CBC-HS512" // AES-CBC + HMAC-SHA512 (256)
	A128GCM       ContentEncryptionAlgorithm = "A128GCM"       // AES-GCM (128)
	A192GCM       ContentEncryptionAlgorithm = "A192GCM"       // AES-GCM (192)
	A256GCM       ContentEncryptionAlgorithm = "A256GCM"       // AES-GCM (256)
)

// CompressionAlgorithm represents the compression algorithms
// as described in https://tools.ietf.org/html/rfc7518#section-7.3
type CompressionAlgorithm string

// Supported CompressionAlgorithms
const (
	NoCompress CompressionAlgorithm = ""    // No compression
	Deflate    CompressionAlgorithm = "DEF" // DEFLATE (RFC 1951)
)
