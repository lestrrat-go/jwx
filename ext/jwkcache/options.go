package jwkcache

import (
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/option/v3"
)

// RegisterOption is an option for Cache.Register.
type RegisterOption = option.Interface

type identHTTPClient struct{}
type identWaitReady struct{}
type identMaxFetchBodySize struct{}
type identResourceOption struct{}

// WithHTTPClient specifies the HTTP client to use for this resource.
func WithHTTPClient(cli jwk.HTTPClient) RegisterOption {
	return option.New(identHTTPClient{}, cli)
}

// WithWaitReady specifies whether Register should wait until the
// first fetch completes. Default is true.
func WithWaitReady(v bool) RegisterOption {
	return option.New(identWaitReady{}, v)
}

// WithMaxFetchBodySize overrides the max body size for this resource.
func WithMaxFetchBodySize(v int64) RegisterOption {
	return option.New(identMaxFetchBodySize{}, v)
}

// WithConstantInterval sets a constant refresh interval.
func WithConstantInterval(d time.Duration) RegisterOption {
	return option.New(identResourceOption{}, httprc.WithConstantInterval(d))
}

// WithMinInterval sets the minimum refresh interval.
func WithMinInterval(d time.Duration) RegisterOption {
	return option.New(identResourceOption{}, httprc.WithMinInterval(d))
}

// WithMaxInterval sets the maximum refresh interval.
func WithMaxInterval(d time.Duration) RegisterOption {
	return option.New(identResourceOption{}, httprc.WithMaxInterval(d))
}
