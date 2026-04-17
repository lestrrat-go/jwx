package jwx

import "github.com/lestrrat-go/jwx/v4/internal/base64"

// Base64Encoder is the interface for base64 encoding backends.
// The default implementation uses encoding/base64.RawURLEncoding.
// Custom backends can replace the default by passing them to
// [Settings] with [WithBase64Encoder].
type Base64Encoder = base64.Encoder

// Base64Decoder is the interface for base64 decoding backends.
// Extension modules can replace the default by passing them to
// [Settings] with [WithBase64Decoder] in their init().
type Base64Decoder = base64.Decoder
