package jwk

import (
	"crypto"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/internal/option"
)

type Option = option.Interface

const (
	optkeyHTTPClient         = `http-client`
	optkeyThumbprintHash     = `thumbprint-hash`
	optkeyRefreshInterval    = `refresh-interval`
	optkeyMinRefreshInterval = `min-refresh-interval`
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

// WithMinRefreshInterval specifies the minimum refresh interval to be used
// when using AutoRefresh. This value is ONLY used if you did not specify
// a user-supplied static refresh interval via `WithRefreshInterval`.
//
// This value is used as a fallback value when tokens are refreshed.
//
// When we fetch the key from a remote URL, we first look at the max-age
// directive from Cache-Control response header. If this value is present,
// we compare the max-age value and the value specified by this option
// and take the larger one.
//
// Nexst we check for the Expires header, and similarly if the header is
// present, we compare it against the value specified by this option,
// and take the larger one.
//
// Finally, if neither of the above headers are present, we use the
// value specified by this option as the next refresh timing
//
// If unspecified, the minimum refresh interval is 1 hour
func WithMinRefreshInterval(d time.Duration) AutoRefreshOption {
	return &autoRefreshOption{
		option.New(optkeyMinRefreshInterval, d),
	}
}
