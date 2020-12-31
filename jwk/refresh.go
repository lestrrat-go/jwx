package jwk

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type AutoRefresh struct {
	cache          map[string]*Set
	fetching       map[string]chan struct{}
	muCache        sync.RWMutex
	muFetching     sync.Mutex
	newWatchTarget chan *watchTarget
}

type watchTarget struct {
	// The HTTP client to use. The user may opt to use a client who is
	// aware of HTTP caching.
	httpcl *http.Client

	// protects keySet from concurrent access
	// TODO: uncomment later
	// muKeySet *sync.Mutex

	// interval between refreshes
	refreshInterval time.Duration
	url             string

	// The timer for refreshing the keyset. should not be set by anyone
	// other than the refreshing goroutine
	timer *time.Timer
}

func NewAutoRefresh(ctx context.Context) *AutoRefresh {
	af := &AutoRefresh{
		cache:          make(map[string]*Set),
		fetching:       make(map[string]chan struct{}),
		newWatchTarget: make(chan *watchTarget),
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

func (af *AutoRefresh) Fetch(ctx context.Context, url string, options ...AutoRefreshOption) (*Set, error) {
	refreshInterval := time.Hour
	for _, option := range options {
		switch option.Name() {
		case optkeyRefreshInterval:
			refreshInterval = option.Value().(time.Duration)
		}
	}

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
		target := &watchTarget{
			httpcl:          http.DefaultClient,
			refreshInterval: refreshInterval,
			url:             url,
		}

		// The first time around, we need to fetch the keyset
		if err := af.refresh(ctx, target); err != nil {
			return nil, errors.Wrapf(err, `failed to fetch resource pointed by %s`, url)
		}
		// Notify the refresher goroutine that we have a new entry
		af.newWatchTarget <- target

		// first delete the entry from the map, then close the channel or
		// otherwise we may end up getting multiple groutines doing the fetch
		af.muFetching.Lock()
		delete(af.fetching, url)
		af.muFetching.Unlock()

		close(fetchingCh)
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
	selcases := []reflect.SelectCase{
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ctx.Done()),
		},
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(af.newWatchTarget),
		},
	}
	baseidx := len(selcases)
	targets := []*watchTarget{}
	for {
		chosen, recv, recvOK := reflect.Select(selcases)
		switch chosen {
		case 0:
			// <-ctx.Done(). Just bail out of this loop
			return
		case 1:
			// <-newWatchTarget. Add this to the list of cases
			if !recvOK {
				continue
			}

			target, ok := recv.Interface().(*watchTarget)
			if !ok {
				continue
			}

			// iterate through the targets and update the old entry
			// if in case we get a new one (hey, could happen).
			// Otherwise, append it
			var found bool
			for _, t := range targets {
				if t.url == target.url {
					found = true
					break
				}
			}
			if !found {
				targets = append(targets, target)
			}
			target.timer = time.NewTimer(target.refreshInterval)

			selcases = append(selcases, reflect.SelectCase{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(target.timer.C),
			})
		// TODO: case 2, remove from watch list
		default:
			// Time to refresh a target
			target := targets[chosen-baseidx]

			//nolint:errcheck
			go af.refresh(context.Background(), target)

			target.timer.Reset(target.refreshInterval)
		}
	}
}

func (af *AutoRefresh) refresh(ctx context.Context, target *watchTarget) error {
	req, err := http.NewRequest(http.MethodGet, target.url, nil)
	if err != nil {
		return errors.Wrap(err, "failed to new request to remote JWK")
	}

	res, err := target.httpcl.Do(req.WithContext(ctx))
	if err != nil {
		return errors.Wrap(err, "failed to fetch remote JWK")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.Errorf("failed to fetch remote JWK (status = %d)", res.StatusCode)
	}

	keyset, err := Parse(res.Body)
	if err != nil {
		// persist the old key set, even if it may be stale.
		return errors.Wrap(err, `failed to parse JWK`)
	}

	// Got a new key set. replace the keyset in the target
	af.muCache.Lock()
	af.cache[target.url] = keyset
	af.muCache.Unlock()

	return nil
}
