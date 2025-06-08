package jwx

import (
	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/option"
)

type identUseNumber struct{}

type Option = option.Interface

type JSONOption interface {
	Option
	isJSONOption()
}

type jsonOption struct {
	Option
}

func (o *jsonOption) isJSONOption() {}

func newJSONOption(n interface{}, v interface{}) JSONOption {
	return &jsonOption{option.New(n, v)}
}

// WithUseNumber controls whether the jwx package should unmarshal
// JSON objects with the "encoding/json".Decoder.UseNumber feature on.
//
// Default is false.
func WithUseNumber(b bool) JSONOption {
	return newJSONOption(identUseNumber{}, b)
}

var optionListPool = pool.New(allocOptionList, destroyOptionList)
var optionListCancelerPool = pool.New(allocOptionListCanceler, destroyOptionListCanceler)

// OptionsList returns a slice of options that can be used to configure
// functions throughout the jwx package. The returned slice is
// allocated from a pool, so if you would like to shave off some
// allocations, you can use the returned slice and then call
// the cancel function to return the slice back to the pool.
func OptionsList() ([]Option, func()) {
	optionsListPoolPtr := optionListPool.Get()
	canceler := optionListCancelerPool.Get()
	canceler.listPtr = optionsListPoolPtr
	return *optionsListPoolPtr, canceler.cancel
}

func allocOptionList() interface{} {
	ret := make([]Option, 0, 1)
	return &ret
}

func destroyOptionList(v *[]option.Interface) {
	*v = (*v)[:0] // Reset the slice to zero length
}

type optionListCanceler struct {
	listPtr *[]Option
}

func allocOptionListCanceler() interface{} {
	return &optionListCanceler{}
}

func destroyOptionListCanceler(canceler *optionListCanceler) {
	canceler.listPtr = nil
	optionListPool.Put(canceler.listPtr)
}

func (c *optionListCanceler) cancel() {
	optionListPool.Put(c.listPtr)
}
