package tokens

const (
	CloseCurlyBracket  = '}'
	CloseSquareBracket = ']'
	Colon              = ':'
	Comma              = ','
	DoubleQuote        = '"'
	OpenCurlyBracket   = '{'
	OpenSquareBracket  = '['
	Period             = '.'
)

// IsJSONSafeASCII reports whether s can be concatenated into a
// hand-built JSON string literal without escaping. Any byte that
// would require a JSON escape (control bytes, `"`, `\`) or any
// non-ASCII byte disqualifies the value.
func IsJSONSafeASCII(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c < 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// Cryptographic key sizes
const (
	KeySize16 = 16
	KeySize24 = 24
	KeySize32 = 32
	KeySize48 = 48 // A192CBC_HS384 key size
	KeySize64 = 64 // A256CBC_HS512 key size
)

// Bit/byte conversion factors
const (
	BitsPerByte = 8
	BytesPerBit = 1.0 / 8
)

// Key wrapping constants
const (
	KeywrapChunkLen  = 8
	KeywrapRounds    = 6 // RFC 3394 key wrap rounds
	KeywrapBlockSize = 8 // Key wrap block size in bytes
)

// AES-GCM constants
const (
	GCMIVSize  = 12 // GCM IV size in bytes (96 bits)
	GCMTagSize = 16 // GCM tag size in bytes (128 bits)
)

// PBES2 constants.
//
// Per-variant default iteration counts follow OWASP 2023 guidance for
// PBKDF2. HS256 takes the 600k baseline; HS384/HS512 take 210k because
// the larger output reduces the brute-force advantage per iteration.
// These are decrypt-accepted too — the global max cap (maxPBES2Count,
// default 1,000,000) stays above all of them.
const (
	PBES2DefaultIterationsHS256 = 600000
	PBES2DefaultIterationsHS384 = 210000
	PBES2DefaultIterationsHS512 = 210000
	PBES2NullByteSeparator      = 0 // Null byte separator for PBES2
)

// RSA key generation constants
const (
	RSAKeyGenMultiplier = 2 // RSA key generation size multiplier
)
