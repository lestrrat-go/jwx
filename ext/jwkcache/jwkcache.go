// Package jwkcache provides JWK Set caching backed by httprc.
//
// This package was extracted from the jwk package to keep the core
// jwx module free of the httprc dependency. Import and use directly:
//
//	import "github.com/jwx-go/jwkcache"
//
//	cache, err := jwkcache.NewCache(ctx, httprc.NewClient())
//	cache.Register(ctx, url)
//	set, err := cache.Lookup(ctx, url)
package jwkcache

import (
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"
	"sync/atomic"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/option/v3"
)

// HTTPClient is the httprc HTTP client interface.
type HTTPClient = httprc.HTTPClient

// ErrorSink is the httprc error sink interface.
type ErrorSink = httprc.ErrorSink

// TraceSink is the httprc trace sink interface.
type TraceSink = httprc.TraceSink

var maxFetchBodySize atomic.Int64

func init() {
	maxFetchBodySize.Store(10 * 1024 * 1024) // 10 MB default
}

// Cache is a container built on top of httprc that keeps track of
// jwk.Set objects by their source URLs. The sets are refreshed
// automatically behind the scenes.
type Cache struct {
	ctrl httprc.Controller
}

// Transformer converts an HTTP response to a jwk.Set.
type Transformer struct {
	ParseOptions     []jwk.ParseOption
	MaxFetchBodySize int64
}

func (t Transformer) Transform(_ context.Context, res *http.Response) (jwk.Set, error) {
	maxBody := t.MaxFetchBodySize
	if maxBody <= 0 {
		maxBody = maxFetchBodySize.Load()
	}

	buf, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf(`failed to read response body: %w`, err)
	}
	if int64(len(buf)) > maxBody {
		return nil, fmt.Errorf(`response body at %q exceeded max size of %d bytes`, res.Request.URL.String(), maxBody)
	}

	set, err := jwk.Parse(buf, t.ParseOptions...)
	if err != nil {
		return nil, fmt.Errorf(`failed to parse JWK set at %q: %w`, res.Request.URL.String(), err)
	}

	return set, nil
}

// NewCache creates a new Cache.
func NewCache(ctx context.Context, client *httprc.Client) (*Cache, error) {
	ctrl, err := client.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf(`failed to start httprc.Client: %w`, err)
	}
	return &Cache{ctrl: ctrl}, nil
}

// Register registers a URL to be managed by the cache.
func (c *Cache) Register(ctx context.Context, u string, options ...RegisterOption) error {
	var parseOptions []jwk.ParseOption
	var resourceOptions []httprc.NewResourceOption
	var fetchBodySize int64
	var httpClient jwk.HTTPClient
	var hasHTTPClient bool
	waitReady := true
	for _, opt := range options {
		switch opt := opt.(type) {
		case jwk.ParseOption:
			parseOptions = append(parseOptions, opt)
		default:
			switch opt.Ident() {
			case identHTTPClient{}:
				httpClient = option.MustGet[jwk.HTTPClient](opt)
				resourceOptions = append(resourceOptions, httprc.WithHTTPClient(httpClient))
				hasHTTPClient = true
			case identWaitReady{}:
				waitReady = option.MustGet[bool](opt)
			case identMaxFetchBodySize{}:
				fetchBodySize = option.MustGet[int64](opt)
			case identResourceOption{}:
				resourceOptions = append(resourceOptions, option.MustGet[httprc.NewResourceOption](opt))
			}
		}
	}

	if !hasHTTPClient {
		resourceOptions = append(resourceOptions, httprc.WithHTTPClient(jwk.DefaultHTTPClient()))
	}

	r, err := httprc.NewResource[jwk.Set](u, &Transformer{
		ParseOptions:     parseOptions,
		MaxFetchBodySize: fetchBodySize,
	}, resourceOptions...)
	if err != nil {
		return fmt.Errorf(`failed to create httprc.Resource: %w`, err)
	}
	if err := c.ctrl.Add(ctx, r, httprc.WithWaitReady(waitReady)); err != nil {
		return fmt.Errorf(`failed to add resource: %w`, err)
	}
	return nil
}

// LookupResource returns the underlying httprc resource for the given URL.
func (c *Cache) LookupResource(ctx context.Context, u string) (*httprc.ResourceBase[jwk.Set], error) {
	r, err := c.ctrl.Lookup(ctx, u)
	if err != nil {
		return nil, fmt.Errorf(`failed to lookup resource %q: %w`, u, err)
	}
	//nolint:forcetypeassert
	return r.(*httprc.ResourceBase[jwk.Set]), nil
}

// Lookup retrieves the cached jwk.Set for the given URL.
func (c *Cache) Lookup(ctx context.Context, u string) (jwk.Set, error) {
	r, err := c.LookupResource(ctx, u)
	if err != nil {
		return nil, fmt.Errorf(`failed to lookup resource %q: %w`, u, err)
	}
	set := r.Resource()
	if set == nil {
		return nil, fmt.Errorf(`resource %q is not ready`, u)
	}
	return set, nil
}

// Ready returns true if the given URL's resource is ready.
func (c *Cache) Ready(ctx context.Context, u string) bool {
	r, err := c.LookupResource(ctx, u)
	if err != nil {
		return false
	}
	return r.Ready(ctx) == nil
}

// Refresh re-fetches the resource and updates the cache.
func (c *Cache) Refresh(ctx context.Context, u string) (jwk.Set, error) {
	if err := c.ctrl.Refresh(ctx, u); err != nil {
		return nil, fmt.Errorf(`failed to refresh resource %q: %w`, u, err)
	}
	return c.Lookup(ctx, u)
}

// IsRegistered returns true if the URL has been registered.
func (c *Cache) IsRegistered(ctx context.Context, u string) bool {
	_, err := c.LookupResource(ctx, u)
	return err == nil
}

// Unregister removes the URL from the cache.
func (c *Cache) Unregister(ctx context.Context, u string) error {
	return c.ctrl.Remove(ctx, u)
}

// Shutdown stops the cache controller.
func (c *Cache) Shutdown(ctx context.Context) error {
	return c.ctrl.ShutdownContext(ctx)
}

// CachedSet returns a jwk.Set backed by the cache. All mutation
// operations on the returned set return errors.
func (c *Cache) CachedSet(u string) (jwk.Set, error) {
	r, err := c.LookupResource(context.Background(), u)
	if err != nil {
		return nil, fmt.Errorf(`failed to lookup resource %q: %w`, u, err)
	}
	return NewCachedSet(r), nil
}

// NewCachedSet creates a read-only jwk.Set backed by an httprc resource.
func NewCachedSet(r *httprc.ResourceBase[jwk.Set]) jwk.Set {
	return &cachedSet{r: r}
}

// Fetcher wraps a Cache as a jwk.Fetcher.
type Fetcher struct {
	cache *Cache
}

// NewFetcher creates a Fetcher backed by the given Cache.
func NewFetcher(cache *Cache) *Fetcher {
	return &Fetcher{cache: cache}
}

// Fetch implements jwk.Fetcher.
func (f *Fetcher) Fetch(ctx context.Context, u string, _ ...jwk.FetchOption) (jwk.Set, error) {
	if !f.cache.IsRegistered(ctx, u) {
		return nil, fmt.Errorf(`jwkcache.Fetcher: url %q has not been registered`, u)
	}
	return f.cache.Lookup(ctx, u)
}

// cachedSet is a read-only jwk.Set backed by a cached resource.
type cachedSet struct {
	r *httprc.ResourceBase[jwk.Set]
}

func (cs *cachedSet) cached() (jwk.Set, error) {
	if err := cs.r.Ready(context.Background()); err != nil {
		return nil, fmt.Errorf(`failed to fetch resource: %w`, err)
	}
	return cs.r.Resource(), nil
}

func (*cachedSet) AddKey(_ jwk.Key) error {
	return fmt.Errorf(`jwkcache.CachedSet is immutable`)
}

func (*cachedSet) Clear() error {
	return fmt.Errorf(`jwkcache.CachedSet is immutable`)
}

func (*cachedSet) Set(_ string, _ any) error {
	return fmt.Errorf(`jwkcache.CachedSet is immutable`)
}

func (*cachedSet) Remove(_ string) error {
	return fmt.Errorf(`jwkcache.CachedSet is immutable`)
}

func (*cachedSet) RemoveKey(_ jwk.Key) error {
	return fmt.Errorf(`jwkcache.CachedSet is immutable`)
}

func (cs *cachedSet) Clone() (jwk.Set, error) {
	set, err := cs.cached()
	if err != nil {
		return nil, err
	}
	return set.Clone()
}

func (cs *cachedSet) Field(name string) (any, bool) {
	set, err := cs.cached()
	if err != nil {
		return nil, false
	}
	return set.Field(name)
}

func (cs *cachedSet) Key(idx int) (jwk.Key, bool) {
	set, err := cs.cached()
	if err != nil {
		return nil, false
	}
	return set.Key(idx)
}

func (cs *cachedSet) Index(key jwk.Key) int {
	set, err := cs.cached()
	if err != nil {
		return -1
	}
	return set.Index(key)
}

func (cs *cachedSet) Keys() []string {
	set, err := cs.cached()
	if err != nil {
		return nil
	}
	return set.Keys()
}

func (cs *cachedSet) Len() int {
	set, err := cs.cached()
	if err != nil {
		return -1
	}
	return set.Len()
}

func (cs *cachedSet) LookupKeyID(kid string) (jwk.Key, bool) {
	set, err := cs.cached()
	if err != nil {
		return nil, false
	}
	return set.LookupKeyID(kid)
}

func (cs *cachedSet) All() iter.Seq2[int, jwk.Key] {
	set, err := cs.cached()
	if err != nil {
		return func(func(int, jwk.Key) bool) {}
	}
	return set.All()
}

func (cs *cachedSet) Fields() iter.Seq2[string, any] {
	set, err := cs.cached()
	if err != nil {
		return func(func(string, any) bool) {}
	}
	return set.Fields()
}

func (cs *cachedSet) MarshalJSON() ([]byte, error) {
	set, err := cs.cached()
	if err != nil {
		return nil, err
	}
	return set.(interface{ MarshalJSON() ([]byte, error) }).MarshalJSON()
}

func (cs *cachedSet) UnmarshalJSON(data []byte) error {
	return fmt.Errorf(`jwkcache.CachedSet is immutable`)
}
