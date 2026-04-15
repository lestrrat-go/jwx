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
