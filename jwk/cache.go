package jwk

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lestrrat-go/httprc"
)

type Transformer = httprc.Transformer
type HTTPClient = httprc.HTTPClient
type ErrSink = httprc.ErrSink
type Whitelist = httprc.Whitelist

// Cache is a container that keeps track of Set object by their source URLs.
// The Set objects are stored in memory, and are refreshed automatically
// behind the scenes.
//
// Before retrieving the Set objects, the user must pre-register the
// URLs they intend to use by calling `Register()`
//
//  c := jwk.New(ctx)
//  c.Register(url, options...)
//
// Once registered, you can call `Get()` to retrieve the Set object.
//
// All JWKS objects that are retrieved via this mechanism should be
// treated read-only, as they are shared among the consumers and this object.
type Cache struct {
	cache *httprc.Cache
}

// PostFetcher is an interface for objects that want to perform
// operations on the `Set` that was fetched.
type PostFetcher interface {
	// PostFetch revceives the URL and the JWKS, after a successful
	// fetch and parse.
	//
	// It should return a `Set`, optionally modified, to be stored
	// in the cache for subsequent use
	PostFetch(string, Set) (Set, error)
}

// PostFetchFunc is a PostFetcher based on a functon.
type PostFetchFunc func(string, Set) (Set, error)

func (f PostFetchFunc) PostFetch(u string, set Set) (Set, error) {
	return f(u, set)
}

// httprc.Transofmer that transforms the response into a JWKS
type jwksTransform struct {
	postFetch    PostFetcher
	parseOptions []ParseOption
}

// Default transform has no postFetch. This can be shared
// by multiple fetchers
var defaultTransform = &jwksTransform{}

func (t *jwksTransform) Transform(u string, res *http.Response) (interface{}, error) {
	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf(`failed to read response body status: %w`, err)
	}

	set, err := Parse(buf, t.parseOptions...)
	if err != nil {
		return nil, fmt.Errorf(`failed to parse JWK set at %q: %w`, u, err)
	}

	if pf := t.postFetch; pf != nil {
		v, err := pf.PostFetch(u, set)
		if err != nil {
			return nil, fmt.Errorf(`failed to execute PostFetch: %w`, err)
		}
		set = v
	}

	return set, nil
}

// NewCache creates a new `jwk.Cache` object.
//
// Please refer to the documentation for `httprc.New` for more
// details.
func NewCache(ctx context.Context, options ...CacheOption) *Cache {
	var hrcopts []httprc.CacheOption
	for _, option := range options {
		switch option.Ident() {
		case identRefreshWindow{}:
			hrcopts = append(hrcopts, httprc.WithRefreshWindow(option.Value().(time.Duration)))
		case identErrSink{}:
			hrcopts = append(hrcopts, httprc.WithErrSink(option.Value().(ErrSink)))
		}
	}

	return &Cache{
		cache: httprc.NewCache(ctx, hrcopts...),
	}
}

// Register registers a URL to be managed by the cache. URLs must
// be registered before issuing `Get`
//
// This method is almost identical to `(httprc.Cache).Register`, except
// it accepts some extra options.
//
// Use `jwk.WithParser` to configure how the JWKS should be parsed,
// such as passing it extra options.
//
// Please refer to the documentation for `(httprc.Cache).Register` for more
// details.
func (c *Cache) Register(u string, options ...RegisterOption) error {
	var hrropts []httprc.RegisterOption
	var pf PostFetcher
	var parseOptions []ParseOption

	// Note: we do NOT accept Transform option
	for _, option := range options {
		if parseOpt, ok := option.(ParseOption); ok {
			parseOptions = append(parseOptions, parseOpt)
			continue
		}

		//nolint:forcetypeassert
		switch option.Ident() {
		case identHTTPClient{}:
			hrropts = append(hrropts, httprc.WithHTTPClient(option.Value().(HTTPClient)))
		case identRefreshInterval{}:
			hrropts = append(hrropts, httprc.WithRefreshInterval(option.Value().(time.Duration)))
		case identMinRefreshInterval{}:
			hrropts = append(hrropts, httprc.WithMinRefreshInterval(option.Value().(time.Duration)))
		case identFetchWhitelist{}:
			hrropts = append(hrropts, httprc.WithWhitelist(option.Value().(httprc.Whitelist)))
		case identPostFetcher{}:
			pf = option.Value().(PostFetcher)
		}
	}

	var t *jwksTransform
	if pf == nil && len(parseOptions) == 0 {
		t = defaultTransform
	} else {
		// User-supplied PostFetcher is attached to the transformer
		t = &jwksTransform{
			postFetch:    pf,
			parseOptions: parseOptions,
		}
	}

	// Set the transfomer at the end so that nobody can override it
	hrropts = append(hrropts, httprc.WithTransformer(t))
	return c.cache.Register(u, hrropts...)
}

// Get returns the stored JWK set (`Set`) from the cache.
//
// Please refer to the documentation for `(httprc.Cache).Get` for more
// details.
func (c *Cache) Get(ctx context.Context, u string) (Set, error) {
	v, err := c.cache.Get(ctx, u)
	if err != nil {
		return nil, err
	}

	set, ok := v.(Set)
	if !ok {
		return nil, fmt.Errorf(`cached object is not a Set (was %T)`, v)
	}
	return set, nil
}

// Refresh is identical to Get(), except it always fetches the
// specified resource anew, and updates the cached content
//
// Please refer to the documentation for `(httprc.Cache).Refresh` for
// more details
func (c *Cache) Refresh(ctx context.Context, u string) (Set, error) {
	v, err := c.cache.Refresh(ctx, u)
	if err != nil {
		return nil, err
	}

	set, ok := v.(Set)
	if !ok {
		return nil, fmt.Errorf(`cached object is not a Set (was %T)`, v)
	}
	return set, nil
}

// IsRegistered returns true if the given URL `u` has already been registered
// in the cache.
//
// Please refer to the documentation for `(httprc.Cache).IsRegistered` for more
// details.
func (c *Cache) IsRegistered(u string) bool {
	return c.cache.IsRegistered(u)
}

// Unregister removes the given URL `u` from the cache.
//
// Please refer to the documentation for `(httprc.Cache).Unregister` for more
// details.
func (c *Cache) Unregister(u string) error {
	return c.cache.Unregister(u)
}

func (c *Cache) Snapshot() *httprc.Snapshot {
	return c.cache.Snapshot()
}
