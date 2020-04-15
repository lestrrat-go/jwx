package jwe

import "github.com/lestrrat-go/jwx/internal/option"

func WithPrettyJSONFormat(b bool) Option {
	return option.New(optkeyPrettyJSONFormat, b)
}
