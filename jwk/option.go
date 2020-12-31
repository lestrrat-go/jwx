package jwk

import (
	"crypto"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/internal/option"
)

type Option = option.Interface

const (
	optkeyHTTPClient      = `http-client`
	optkeyThumbprintHash  = `thumbprint-hash`
	optkeyRefreshInterval = `refresh-interval`
)

func WithHTTPClient(cl *http.Client) AutoRefreshOption {
	return &autoRefreshOption{
		option.New(optkeyHTTPClient, cl),
	}
}

func WithThumbprintHash(h crypto.Hash) Option {
	return option.New(optkeyThumbprintHash, h)
}

type autoRefreshOption struct {
	Option
}

func (aro *autoRefreshOption) autoRefreshOption() bool {
	return true
}

func WithRefreshInterval(d time.Duration) AutoRefreshOption {
	return &autoRefreshOption{
		option.New(optkeyRefreshInterval, d),
	}
}
