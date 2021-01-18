package fs

import "github.com/lestrrat-go/option"

type Option = option.Interface

type OpenOption interface {
	Option
	openOption()
}

type openOption struct {
	Option
}

// Wrap another option and make it an OpenOption
func NewOpenOption(o Option) OpenOption {
	return &openOption{o}
}

func (o *openOption) openOption() {}
