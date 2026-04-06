package jwk

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// defaultMaxFetchBodySize is the initial default maximum number of bytes read
// from an HTTP response body when fetching a JWKS (10 MB).
const defaultMaxFetchBodySize int64 = 10 * 1024 * 1024

// defaultFetchTimeout is the default timeout for HTTP requests made by
// jwk.Fetch(). This prevents malicious or unresponsive JWKS endpoints from
// hanging indefinitely (e.g. slowloris-style DoS).
const defaultFetchTimeout = 30 * time.Second

// defaultMaxRedirects is the maximum number of HTTP redirects the default
// fetch client will follow. This is intentionally lower than Go's default
// of 10 to limit redirect chain abuse.
const defaultMaxRedirects = 5

// HTTPClient is an interface for HTTP clients used by jwk.Fetch and
// related functions.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

var maxFetchBodySize atomic.Int64

var (
	fetchHTTPClientMu sync.RWMutex
	fetchHTTPClient   HTTPClient
)

func init() {
	maxFetchBodySize.Store(defaultMaxFetchBodySize)
	fetchHTTPClient = DefaultHTTPClient()
}

// DefaultHTTPClient returns a new http.Client configured with the same
// defaults used by jwk.Fetch(): a 30-second timeout, a redirect policy
// that blocks HTTPS-to-HTTP scheme downgrades, and a maximum of 5 redirects.
//
// This is useful for callers who need the library's default protections
// but want to wrap or augment the client (e.g. adding a custom Transport),
// and for restoring defaults after calling jwk.Configure(jwk.WithHTTPClient(...)).
func DefaultHTTPClient() *http.Client {
	return WrapHTTPClientDefaults(&http.Client{})
}

// WrapHTTPClientDefaults returns a shallow copy of the given http.Client with the
// library's default safety behaviors applied. Existing client settings
// (Transport, Jar, etc.) are preserved.
//
//   - Timeout: applied only when the client has no timeout set (zero value).
//   - CheckRedirect: if the client already has one, the library's redirect
//     policy runs first; if it passes, the original CheckRedirect is called.
//     If the client has no CheckRedirect, the library's policy is used directly.
//
// This is useful when you need to bring your own http.Client (e.g. for custom
// TLS configuration) but still want the library's redirect hardening.
func WrapHTTPClientDefaults(client *http.Client) *http.Client {
	cloned := *client
	if cloned.Timeout == 0 {
		cloned.Timeout = defaultFetchTimeout
	}
	orig := cloned.CheckRedirect
	if orig == nil {
		cloned.CheckRedirect = defaultCheckRedirect
	} else {
		cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if err := defaultCheckRedirect(req, via); err != nil {
				return err
			}
			return orig(req, via)
		}
	}
	return &cloned
}

// defaultCheckRedirect is the CheckRedirect policy for the default HTTP client
// used by jwk.Fetch(). It prevents HTTPS-to-HTTP scheme downgrades and limits
// the total number of redirects.
//
// This does NOT protect against redirects to private/internal IP addresses.
// For full SSRF protection, callers should provide a custom http.Client via
// WithHTTPClient that validates destination IPs in Transport.DialContext.
func defaultCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= defaultMaxRedirects {
		return fmt.Errorf("jwk.Fetch: stopped after %d redirects", defaultMaxRedirects)
	}

	// Prevent HTTPS → HTTP scheme downgrade at any hop.
	// via[len(via)-1] is the immediately previous request in the chain.
	if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("jwk.Fetch: redirect from HTTPS to non-HTTPS URL %q is not allowed", req.URL.Redacted())
	}
	return nil
}

func getFetchHTTPClient() HTTPClient {
	fetchHTTPClientMu.RLock()
	defer fetchHTTPClientMu.RUnlock()
	return fetchHTTPClient
}

func setFetchHTTPClient(c HTTPClient) {
	fetchHTTPClientMu.Lock()
	defer fetchHTTPClientMu.Unlock()
	fetchHTTPClient = c
}

// Fetcher is an interface that represents an object that fetches a JWKS.
// Currently this is only used in the `jws.WithVerifyAuto` option.
//
// Particularly, do not confuse this as the backend to `jwk.Fetch()` function.
// If you need to control how `jwk.Fetch()` implements HTTP requests look into
// providing a custom `http.Client` object via `jwk.WithHTTPClient` option
type Fetcher interface {
	Fetch(context.Context, string, ...FetchOption) (Set, error)
}

// FetchFunc describes a type of Fetcher that is represented as a function.
//
// You can use this to wrap functions (e.g. `jwk.Fetch“) as a Fetcher object.
type FetchFunc func(context.Context, string, ...FetchOption) (Set, error)

func (ff FetchFunc) Fetch(ctx context.Context, u string, options ...FetchOption) (Set, error) {
	return ff(ctx, u, options...)
}

// Fetch fetches a JWK resource specified by a URL. The url must be
// pointing to a resource that is supported by `net/http`.
//
// This function is just a wrapper around `net/http` and `jwk.Parse`.
// There is nothing special here, so you are safe to use your own
// mechanism to fetch the JWKS.
//
// If you are using the same `jwk.Set` for long periods of time during
// the lifecycle of your program, and would like to periodically refresh the
// contents of the object with the data at the remote resource,
// consider using `jwk.Cache`, which automatically refreshes
// jwk.Set objects asynchronously.
func Fetch(ctx context.Context, u string, options ...FetchOption) (Set, error) {
	var parseOptions []ParseOption
	//nolint:revive // I want to keep the type of `wl` as `Whitelist` instead of `InsecureWhitelist`
	var wl Whitelist = InsecureWhitelist{}
	var client = getFetchHTTPClient()
	var maxBodySize = maxFetchBodySize.Load()
	for _, opt := range options {
		// Process fetch-specific options first, before falling through
		// to collect parse options. Some options (e.g. GlobalFetchOption)
		// satisfy both FetchOption and ParseOption.
		switch opt.Ident() {
		case identHTTPClient{}:
			client = option.MustGet[HTTPClient](opt)
			continue
		case identFetchWhitelist{}:
			wl = option.MustGet[Whitelist](opt)
			continue
		case identMaxFetchBodySize{}:
			maxBodySize = option.MustGet[int64](opt)
			if maxBodySize <= 0 {
				return nil, fmt.Errorf(`jwk.Fetch: WithMaxFetchBodySize must be greater than zero`)
			}
			continue
		}

		if parseOpt, ok := opt.(ParseOption); ok {
			parseOptions = append(parseOptions, parseOpt)
		}
	}

	if !wl.IsAllowed(u) {
		return nil, whitelistError{fmt.Errorf(`jwk.Fetch: url %q has been rejected by whitelist`, u)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf(`jwk.Fetch: failed to create new request: %w`, err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf(`jwk.Fetch: request failed: %w`, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(`jwk.Fetch: request returned status %d, expected 200`, res.StatusCode)
	}

	// LimitReader caps memory at maxBodySize+1; reading +1 byte lets us detect
	// oversized responses. We intentionally skip a Content-Length pre-check because
	// the header is untrustworthy (server-controlled, absent in chunked transfers).
	// Slow-trickle attacks are mitigated by context deadlines and http.Client.Timeout,
	// not by header inspection.
	buf, err := io.ReadAll(io.LimitReader(res.Body, maxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf(`jwk.Fetch: failed to read response body for %q: %w`, u, err)
	}
	if int64(len(buf)) > maxBodySize {
		return nil, fmt.Errorf(`jwk.Fetch: response body for %q exceeded max size of %d bytes`, u, maxBodySize)
	}

	return Parse(buf, parseOptions...)
}
