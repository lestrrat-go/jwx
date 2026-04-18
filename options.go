package jwx

import "github.com/lestrrat-go/option/v3"

type Option = option.Interface

// GlobalOption describes an Option that can be passed to `jwx.Settings()`.
type GlobalOption interface {
	Option
	globalOption()
}

type globalOption struct {
	Option
}

func (*globalOption) globalOption() {}

type identUseNumber struct{}

// WithUseNumber controls whether the jwx package should unmarshal
// JSON numbers in private/custom fields as json.Number instead of
// float64. This preserves numeric precision for large integers.
//
// This setting has process-global effect and must be applied once
// at program startup (typically from func init() or early in main())
// before any goroutine begins parsing JWx payloads. The underlying
// flag is read atomically, so toggling it at runtime is race-free,
// but any in-flight or subsequent decoders will observe a mix of
// float64 and json.Number values in concurrently-decoded custom
// fields — callers that type-assert on those values will break
// non-deterministically. There is no per-call override.
//
// Default is false.
func WithUseNumber(v bool) GlobalOption {
	return &globalOption{option.New(identUseNumber{}, v)}
}

type identBase64Encoder struct{}

// WithBase64Encoder replaces the base64 encoder used by the library.
// The default implementation uses encoding/base64.RawURLEncoding.
//
// This setting has process-global effect and must be applied once
// at program startup (typically from func init() or early in main())
// before any goroutine begins encoding JWx payloads. The underlying
// encoder is read atomically, so swapping it at runtime is race-free,
// but any in-flight or subsequent encoders will observe a mix of
// backends in concurrently-encoded outputs. There is no per-call
// override at this layer; per-operation overrides exist on the
// jws/jwt packages (see jws.WithBase64Encoder / jwt.WithBase64Encoder).
func WithBase64Encoder(v Base64Encoder) GlobalOption {
	return &globalOption{option.New(identBase64Encoder{}, v)}
}

type identBase64Decoder struct{}

// WithBase64Decoder replaces the base64 decoder used by the library.
// The default implementation detects the encoding variant of the input
// and decodes accordingly.
//
// This setting has process-global effect and must be applied once
// at program startup (typically from func init() or early in main())
// before any goroutine begins decoding JWx payloads. The underlying
// decoder is read atomically, so swapping it at runtime is race-free,
// but any in-flight or subsequent decoders will observe a mix of
// backends for concurrently-decoded inputs. There is no per-call
// override.
func WithBase64Decoder(v Base64Decoder) GlobalOption {
	return &globalOption{option.New(identBase64Decoder{}, v)}
}
