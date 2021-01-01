package jwk

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/lestrrat-go/httpcc"
	"github.com/pkg/errors"
)

type AutoRefresh struct {
	cache       map[string]*Set
	configureCh chan struct{}
	fetching    map[string]chan struct{}
	muCache     sync.RWMutex
	muFetching  sync.Mutex
	muRegistry  sync.RWMutex
	registry    map[string]*target
}

type target struct {
	// The HTTP client to use. The user may opt to use a client who is
	// aware of HTTP caching.
	httpcl *http.Client

	// protects keySet from concurrent access
	// TODO: uncomment later
	// muKeySet *sync.Mutex

	// Interval between refreshes are calculated two ways.
	// 1) You can set an explicit refresh interval by using WithRefreshInterval().
	//    In this mode, it doesn't matter what the HTTP response says in its
	//    Cache-Control or Expires headers
	// 2) You can let us calculate the time-to-refresh based on the key's
	//	  Cache-Control or Expires headers.
	//    First, the user provides us the absolute minimum interval before
	//    refreshes. We will never check for refreshes before this specified
	//    amount of time.
	//
	//    Next, max-age directive in the Cache-Control header is consulted.
	//    If `max-age` is not present, we skip the following section, and
	//    proceed to the next option.
	//    If `max-age > user-supplied minimum interval`, then we use the max-age,
	//    otherwise the user-supplied minimum interval is used.
	//
	//    Next, the value specified in Expires header is consulted.
	//    If the header is not present, we skip the following seciont and
	//    proceed to the next option.
	//    We take the time until expiration `expires - time.Now()`, and
	//	  if `time-until-expiration > user-supplied minimum interval`, then
	//    we use the expires value, otherwise the user-supplied minimum interval is used.
	//
	//    If all of the above fails, we used the user-supplied minimum interval
	refreshInterval    *time.Duration
	minRefreshInterval time.Duration

	url string

	// The timer for refreshing the keyset. should not be set by anyone
	// other than the refreshing goroutine
	timer *time.Timer
}

func NewAutoRefresh(ctx context.Context) *AutoRefresh {
	af := &AutoRefresh{
		cache:       make(map[string]*Set),
		configureCh: make(chan struct{}),
		fetching:    make(map[string]chan struct{}),
		registry:    make(map[string]*target),
	}
	go af.refreshLoop(ctx)
	return af
}

func (af *AutoRefresh) getCached(url string) (*Set, bool) {
	af.muCache.RLock()
	ks, ok := af.cache[url]
	af.muCache.RUnlock()
	if ok {
		return ks, true
	}
	return nil, false
}

func (af *AutoRefresh) configure(url string, options ...AutoRefreshOption) {
	httpcl := http.DefaultClient
	var hasRefreshInterval bool
	var refreshInterval time.Duration
	minRefreshInterval := time.Hour
	for _, option := range options {
		switch option.Name() {
		case optkeyRefreshInterval:
			refreshInterval = option.Value().(time.Duration)
			hasRefreshInterval = true
		case optkeyMinRefreshInterval:
			minRefreshInterval = option.Value().(time.Duration)
		case optkeyHTTPClient:
			httpcl = option.Value().(*http.Client)
		}
	}

	var doReconfigure bool
	af.muRegistry.Lock()
	t, ok := af.registry[url]
	if ok {
		if t.httpcl != httpcl {
			t.httpcl = httpcl
			doReconfigure = true
		}

		if t.minRefreshInterval != minRefreshInterval {
			t.minRefreshInterval = minRefreshInterval
			doReconfigure = true
		}

		if t.refreshInterval != nil {
			if !hasRefreshInterval {
				t.refreshInterval = nil
				doReconfigure = true
			} else if *t.refreshInterval != refreshInterval {
				*t.refreshInterval = refreshInterval
				doReconfigure = true
			}
		} else {
			if hasRefreshInterval {
				t.refreshInterval = &refreshInterval
				doReconfigure = true
			}
		}
	} else {
		t = &target{
			httpcl:             httpcl,
			minRefreshInterval: minRefreshInterval,
			url:                url,
			// This is a placeholder timer so we can call Reset() on it later
			// Make it sufficiently in the future so that we don't have bogus
			// events firing
			timer: time.NewTimer(24 * time.Hour),
		}
		if hasRefreshInterval {
			t.refreshInterval = &refreshInterval
		}

		// Record this in the registry
		af.registry[url] = t
		doReconfigure = true
	}
	af.muRegistry.Unlock()

	if doReconfigure {
		// Tell the backend to reconfigure itself
		af.configureCh <- struct{}{}
	}
}

func (af *AutoRefresh) releaseFetching(url string) {
	// first delete the entry from the map, then close the channel or
	// otherwise we may end up getting multiple groutines doing the fetch
	af.muFetching.Lock()
	fetchingCh, ok := af.fetching[url]
	if !ok {
		// Juuuuuuust in case. But shouldn't happen
		af.muFetching.Unlock()
		return
	}
	delete(af.fetching, url)
	close(fetchingCh)
	af.muFetching.Unlock()
}

func (af *AutoRefresh) Fetch(ctx context.Context, url string, options ...AutoRefreshOption) (*Set, error) {
	ks, found := af.getCached(url)
	if found {
		return ks, nil
	}

	// To avoid a thundering herd, only one goroutine per url may enter into this
	// initial fetch phase.
	af.muFetching.Lock()
	fetchingCh, fetching := af.fetching[url]
	// unlock happens in each of the if/else clauses because we need to perform
	// the channel initialization when there is no channel present
	if fetching {
		af.muFetching.Unlock()
		<-fetchingCh
	} else {
		fetchingCh = make(chan struct{})
		af.fetching[url] = fetchingCh
		af.muFetching.Unlock()

		// Register a cleanup handler, to make sure we always
		defer af.releaseFetching(url)

		af.configure(url, options...)

		// The first time around, we need to fetch the keyset
		if err := af.refresh(ctx, url); err != nil {
			return nil, errors.Wrapf(err, `failed to fetch resource pointed by %s`, url)
		}
	}

	// the cache should now be populated
	ks, ok := af.getCached(url)
	if !ok {
		panic("cache was not populated after explicit refresh")
	}

	return ks, nil
}

// Keeps looping, while refreshing the KeySet.
func (af *AutoRefresh) refreshLoop(ctx context.Context) {
	// reflect.Select() is slow IF we are executing it over and over
	// in a very fast iteration, but we assume here that refreshes happen
	// seldom enough that being able to call one `select{}` with multiple
	// targets / channels outweighs the speed penalty of using reflect.
	baseSelcases := []reflect.SelectCase{
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ctx.Done()),
		},
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(af.configureCh),
		},
	}
	baseidx := len(baseSelcases)

	var targets []*target
	var selcases []reflect.SelectCase
	for {
		// It seems silly, but it's much easier to keep track of things
		// if we re-build the select cases every iteration

		af.muRegistry.RLock()
		if cap(targets) < len(af.registry) {
			targets = make([]*target, 0, len(af.registry))
		} else {
			targets = targets[:0]
		}

		if cap(selcases) < len(af.registry) {
			selcases = make([]reflect.SelectCase, 0, len(af.registry)+baseidx)
		} else {
			selcases = selcases[:0]
		}
		selcases = append(selcases, baseSelcases...)

		for _, data := range af.registry {
			targets = append(targets, data)
			selcases = append(selcases, reflect.SelectCase{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(data.timer.C),
			})
		}
		af.muRegistry.RUnlock()

		chosen, _, _ := reflect.Select(selcases)
		switch chosen {
		case 0:
			// <-ctx.Done(). Just bail out of this loop
			return
		case 1:
			// <-configureCh. rebuild the select list from the registry.
			// since we're rebuilding everything for each iteration,
			// we just need to start the loop all over again
			continue
		default:
			// Time to refresh a target
			t := targets[chosen-baseidx]

			//nolint:errcheck
			go af.refresh(context.Background(), t.url)
		}
	}
}

func resetTimer(res *http.Response, t *target) {
	refreshInterval := calculateRefreshDuration(res, t.refreshInterval, t.minRefreshInterval)
	if !t.timer.Stop() {
		select {
		case <-t.timer.C:
		default:
		}
	}
	t.timer.Reset(refreshInterval)
}

func (af *AutoRefresh) refresh(ctx context.Context, url string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return errors.Wrap(err, "failed to new request to remote JWK")
	}

	af.muRegistry.RLock()
	t, ok := af.registry[url]
	af.muRegistry.RUnlock()

	if !ok {
		return errors.Errorf(`url "%s" is not registered`, url)
	}

	res, err := t.httpcl.Do(req.WithContext(ctx))
	if err != nil {
		return errors.Wrap(err, "failed to fetch remote JWK")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.Errorf("failed to fetch remote JWK (status = %d)", res.StatusCode)
	}

	// Register this cleanup handler so that we setup a new timer even
	// in case of a parse failure
	defer resetTimer(res, t)

	keyset, err := Parse(res.Body)
	if err != nil {
		// We don't delete the old key. We persist the old key set, even if it may be stale.
		// so the user has something to work with
		// TODO: maybe this behavior should be customizable?
		return errors.Wrap(err, `failed to parse JWK`)
	}

	// Got a new key set. replace the keyset in the target
	af.muCache.Lock()
	af.cache[url] = keyset
	af.muCache.Unlock()

	return nil
}

func calculateRefreshDuration(res *http.Response, refreshInterval *time.Duration, minRefreshInterval time.Duration) time.Duration {
	// This always has precedence
	if refreshInterval != nil {
		return *refreshInterval
	}

	if v := res.Header.Get(`Cache-Control`); v != "" {
		dir, err := httpcc.ParseResponse(res.Header.Get(`Cache-Control`))
		if err == nil {
			maxAge, ok := dir.MaxAge()
			if ok {
				resDuration := time.Duration(maxAge) * time.Second
				if resDuration > minRefreshInterval {
					return resDuration
				}
				return minRefreshInterval
			}
			// fallthrough
		}
		// fallthrough
	}

	if v := res.Header.Get(`Expires`); v != "" {
		expires, err := http.ParseTime(v)
		if err == nil {
			resDuration := time.Until(expires)
			if resDuration > minRefreshInterval {
				return resDuration
			}
			return minRefreshInterval
		}
		// fallthrough
	}

	// Previous fallthroughs are a little redandunt, but hey, it's all good.
	return minRefreshInterval
}
