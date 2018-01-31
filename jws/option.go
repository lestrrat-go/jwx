package jws

import (
	"github.com/lestrrat/go-jwx/internal/option"
	"github.com/lestrrat/go-jwx/jws/sign"
)

type Option = option.Interface

const (
	optkeyPayloadSigner    = `payload-signer`
	optkeyHeaders          = `headers`
	optkeyPrettyJSONFormat = `format-json-pretty`
)

func WithPretty(b bool) Option {
	return option.New(optkeyPrettyJSONFormat, b)
}

func WithSigner(signer sign.Signer, key interface{}) Option {
	return option.New(optkeyPayloadSigner, &payloadSigner{
		signer: signer,
		key:    key,
	})
}

func WithHeaders(h HeaderInterface) Option {
	return option.New(optkeyHeaders, h)
}
