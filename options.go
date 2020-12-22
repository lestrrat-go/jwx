package jwx

import "github.com/lestrrat-go/jwx/internal/option"

const (
	optkeyUseNumber = "json-use-number"
)

type Option = option.Interface

type JSONOption interface {
	Option
	isJSONOption() bool
}

type jsonOption struct {
	Option
}

func (o *jsonOption) isJSONOption() bool { return true }

func newJSONOption(n string, v interface{}) JSONOption {
	return &jsonOption{
		Option: option.New(n, v),
	}
}

// WithUseNumber controls whether the jwx package should unmarshal
// JSON objects with the "encoding/json".Decoder.UseNumber feature on.
//
// Default is false.
func WithUseNumber(b bool) JSONOption {
	return newJSONOption(optkeyUseNumber, b)
}
