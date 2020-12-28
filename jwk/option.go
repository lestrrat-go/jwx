package jwk

import (
	"crypto"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/internal/option"
)

type Option = option.Interface

const (
	optkeyHTTPClient       = `http-client`
	optkeyThumbprintHash   = `thumbprint-hash`
	optkeyHTTPExpiration   = `http-expiration`
	optkeyManualExpiration = `manual-expiration`
)

func WithHTTPClient(cl *http.Client) Option {
	return option.New(optkeyHTTPClient, cl)
}

func WithThumbprintHash(h crypto.Hash) Option {
	return option.New(optkeyThumbprintHash, h)
}

func WithHTTPExpiration(minDuration time.Duration) Option {
	return option.New(optkeyHTTPExpiration, minDuration)
}

func WithManualExpiration(duration time.Duration) Option {
	return option.New(optkeyManualExpiration, duration)
}
