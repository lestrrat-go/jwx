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
// Default is false.
func WithUseNumber(v bool) GlobalOption {
	return &globalOption{option.New(identUseNumber{}, v)}
}
