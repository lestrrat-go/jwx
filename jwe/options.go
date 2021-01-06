package jwe

import "github.com/lestrrat-go/option"

type Option = option.Interface
type identPrettyJSONFormat struct{}

// WithPrettyJSONFormat specifies if the `jwe.JSON` serialization tool
// should generate pretty-formatted output
func WithPrettyJSONFormat(b bool) Option {
	return option.New(identPrettyJSONFormat{}, b)
}
