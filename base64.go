package jwx

import "github.com/lestrrat-go/jwx/v4/internal/base64"

// Base64Encoder is the interface for base64 encoding backends.
// The default implementation uses encoding/base64.RawURLEncoding.
// Custom backends can replace the default by calling SetBase64Encoder.
type Base64Encoder = base64.Encoder

// Base64Decoder is the interface for base64 decoding backends.
// Extension modules can replace the default by calling SetBase64Decoder
// in their init().
type Base64Decoder = base64.Decoder

// SetBase64Encoder replaces the base64 encoder used by the library.
func SetBase64Encoder(enc Base64Encoder) {
	base64.SetEncoder(enc)
}

// SetBase64Decoder replaces the base64 decoder used by the library.
func SetBase64Decoder(dec Base64Decoder) {
	base64.SetDecoder(dec)
}
