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
	newWatchTarget chan *watchTarget
}

type watchTarget struct {
	// The HTTP client to use. The user may opt to use a client who is
	// aware of HTTP caching.
	httpcl *http.Client

	// The actual keyset. Must be treated as readonly by the end consumer.
	// will be updated asynchronously, therefore muKeySet must be consulted
	// before accessing this
	keySet *Set

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
		newWatchTarget: make(chan *watchTarget),
	}
	go af.refreshLoop(ctx)
	return af
}

func (af *AutoRefresh) Fetch(ctx context.Context, url string, options ...AutoRefreshOption) (*Set, error) {
	refreshInterval := time.Hour
	for _, option := range options {
		switch option.Name() {
		case optkeyRefreshInterval:
			refreshInterval = option.Value().(time.Duration)
		}
	}

	ks, ok := af.cache[url]
	if ok {
		return ks, nil
	}

	// The first time around, we need to fetch the keyset
	target := &watchTarget{
		httpcl:          http.DefaultClient,
		keySet:          ks,
		refreshInterval: refreshInterval,
		url:             url,
	}
	if err := af.refresh(ctx, target); err != nil {
		return nil, errors.Wrapf(err, `failed to fetch resource pointed by %s`, url)
	}

	// new entry. Do the fetch once in a blocking manner
	ks = target.keySet
	af.cache[url] = ks
	af.newWatchTarget <- target

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
	target.keySet = keyset
	af.cache[target.url] = keyset

	return nil
}
