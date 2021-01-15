package jws

import (
	"github.com/lestrrat-go/option"
)

type Option = option.Interface

type identPayloadSigner struct{}
type identHeaders struct{}

func WithSigner(signer Signer, key interface{}, public, protected Headers) Option {
	return option.New(identPayloadSigner{}, &payloadSigner{
		signer:    signer,
		key:       key,
		protected: protected,
		public:    public,
	})
}

func WithHeaders(h Headers) Option {
	return option.New(identHeaders{}, h)
}
