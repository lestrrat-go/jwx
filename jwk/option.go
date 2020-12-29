package jwk

import (
	"crypto"
	"net/http"

	"github.com/gregjones/httpcache"
	"github.com/lestrrat-go/jwx/internal/option"
)

type Option = option.Interface

const (
	optkeyHTTPCache      = `http-cache`
	optkeyHTTPClient     = `http-client`
	optkeyThumbprintHash = `thumbprint-hash`
)

func WithHTTPCache(c httpcache.Cache) Option {
	return option.New(optkeyHTTPCache, c)
}

func WithHTTPClient(cl *http.Client) Option {
	return option.New(optkeyHTTPClient, cl)
}

func WithThumbprintHash(h crypto.Hash) Option {
	return option.New(optkeyThumbprintHash, h)
}
