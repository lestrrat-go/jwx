package jwk

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/lestrrat-go/httprc"
)

type Fetcher interface {
	Fetch(context.Context, string, ...FetchOption) (Set, error)
}

type FetchFunc func(context.Context, string, ...FetchOption) (Set, error)

func (f FetchFunc) Fetch(ctx context.Context, u string, options ...FetchOption) (Set, error) {
	return f(ctx, u, options...)
}

// Fetch fetches a JWK resource specified by a URL. The url must be
// pointing to a resource that is supported by `net/http`.
//
// If you are using the same `jwk.Set` for long periods of time during
// the lifecycle of your program, and would like to periodically refresh the
// contents of the object with the data at the remote resource,
// consider using `jwk.Cache`, which automatically refreshes
// jwk.Set objects asynchronously.
//
// If you need extra
func Fetch(ctx context.Context, u string, options ...FetchOption) (Set, error) {
	var parseOptions []ParseOption
	var wl Whitelist = InsecureWhitelist{}
	var client HTTPClient = http.DefaultClient
	for _, option := range options {
		if parseOpt, ok := option.(ParseOption); ok {
			parseOptions = append(parseOptions, parseOpt)
			continue
		}

		//nolint:forcetypeassert
		switch option.Ident() {
		case identHTTPClient{}:
			client = option.Value().(HTTPClient)
		case identFetchWhitelist{}:
			wl = option.Value().(httprc.Whitelist)
		}
	}

	if !wl.IsAllowed(u) {
		return nil, fmt.Errorf(`jwk.Fetch: url %q has been rejected by whitelist`, u)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf(`jwk.Fetch: failed to create new request: %w`, err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf(`jwk.Fetch: request failed: %w`, err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(`jwk.Fetch: request returned status %d, expected 200`, res.StatusCode)
	}

	buf, err := io.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf(`jwk.Fetch: failed to read response body for %q: %w`, u, err)
	}

	return Parse(buf, parseOptions...)
}
