package jwk

import (
	"context"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/gregjones/httpcache"
	"github.com/pkg/errors"
)

var DefaultHTTPCache = httpcache.NewMemoryCache()

type gatekeepEntry struct {
	ch      chan struct{}
	expires time.Time
}

type Store struct {
	ttl        time.Duration
	gatekeeper map[string]*gatekeepEntry
	muGk       sync.Mutex
}

func NewStore() *Store {
	return &Store{
		ttl:        15 * time.Minute,
		gatekeeper: make(map[string]*gatekeepEntry),
	}
}

func (store *Store) gatekeep(u string) chan struct{} {
	store.muGk.Lock()

	gke, ok := store.gatekeeper[u]
	var newGke bool
	if !ok {
		newGke = true
	} else {
		if gke.expires.Before(time.Now()) {
			delete(store.gatekeeper, u)
			newGke = true
		}
	}

	if newGke {
		gke = &gatekeepEntry{
			ch: make(chan struct{}, 1),
		}
		store.gatekeeper[u] = gke
	}

	gke.expires = time.Now().Add(store.ttl)

	store.muGk.Unlock()

	return gke.ch
}

// Returns the response body as []byte, a boolean indicating if the
// response body came from a cache (true -> came from a cache,
// false -> came from new http request)
func (store *Store) fetchHTTP(ctx context.Context, u string, httpcl *http.Client) ([]byte, bool, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to new request to remote JWK")
	}

	res, err := httpcl.Do(req.WithContext(ctx))
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to fetch remote JWK")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, false, errors.Errorf("failed to fetch remote JWK (status = %d)", res.StatusCode)
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, false, errors.Wrap(err, `failed to read from HTTP body`)
	}

	return buf, res.Header.Get(httpcache.XFromCache) == "1", nil
}

func (store *Store) Fetch(ctx context.Context, u string, options ...Option) (*Set, error) {
	var set *Set
	if err := store.refresh(ctx, u, &set, options...); err != nil {
		return nil, err
	}
	return set, nil
}

func (store *Store) Refresh(ctx context.Context, u string, set **Set, options ...Option) error {
	return store.refresh(ctx, u, set, options...)
}

func (store *Store) refresh(ctx context.Context, u string, set **Set, options ...Option) error {
	ch := store.gatekeep(u)
	ch <- struct{}{}
	defer func() { <-ch }()

	var cache httpcache.Cache = DefaultHTTPCache
	httpcl := http.DefaultClient
	for _, option := range options {
		switch option.Name() {
		case optkeyHTTPClient:
			httpcl = option.Value().(*http.Client)
		case optkeyHTTPCache:
			cache = option.Value().(httpcache.Cache)
		}
	}

	// Use HTTP Caching
	httpcl.Transport = &httpcache.Transport{
		Transport:           httpcl.Transport,
		Cache:               cache,
		MarkCachedResponses: true,
	}

	body, fromCache, err := store.fetchHTTP(ctx, u, httpcl)
	if err != nil {
		return errors.Wrapf(err, `failed to fetch from %s`, u)
	}

	if *set == nil || !fromCache {
		v, err := ParseBytes(body)
		if err != nil {
			return errors.Wrap(err, `failed to parse JWK`)
		}
		*set = v
	}

	return nil
}
