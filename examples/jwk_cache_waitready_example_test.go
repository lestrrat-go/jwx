package examples_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/httprc/v3/errsink"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Example_jwk_cache_waitready demonstrates how to bound the wait performed by
// `jwk.WithWaitReady(true)`, and how to tell "the JWKS endpoint has not
// answered yet" apart from other registration failures.
//
// `(jwk.Cache).Register` with `jwk.WithWaitReady(true)` (the default) blocks
// until the first fetch of the JWKS succeeds. That wait has no timeout of its
// own, because the cache keeps retrying the URL on its refresh schedule and
// only the caller knows how long a JWKS outage at startup is worth waiting
// for. Pass a `context.Context` carrying a deadline to bound it.
//
// When the deadline expires the URL stays registered and the cache keeps
// refreshing it in the background, so the returned error is wrapped in
// `httprc.ErrNotReady()` to distinguish it from a registration that never
// happened. That error says the first fetch has not landed, but not why. The
// reason is delivered to the error sink configured with
// `httprc.WithErrorSink()`, which is where every background fetch failure of
// the cache is reported.
func Example_jwk_cache_waitready() {
	const jwks = `{"keys":[{"crv":"P-256","kid":"example-key","kty":"EC","x":"qwwx4vRPSqtIZXXZapWX3ffw8TFOiJJ0VEtTDhQr4gg","y":"704TQDA5YCeyj60FZehEbNsypCCiK65g5OWD9NTy5iE"}]}`

	// The JWKS endpoint is down until `healthy` is set.
	var healthy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set(`Content-Type`, `application/json`)
		fmt.Fprint(w, jwks)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Collect the background fetch failures so we can report them below. A
	// real application would more likely log them, for which
	// `errsink.NewSlog()` is provided.
	fetchErrs := make(chan error, 1)
	c, err := jwk.NewCache(ctx, httprc.NewClient(
		httprc.WithErrorSink(errsink.NewFunc(func(_ context.Context, err error) {
			select {
			case fetchErrs <- err:
			default: // already holding one; the sink must never block the cache
			}
		})),
	))
	if err != nil {
		fmt.Printf("failed to create cache: %s\n", err)
		return
	}

	// Bound the wait for the first fetch. Without a deadline here, this
	// `Register` call would block for as long as the endpoint keeps failing.
	regCtx, regCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer regCancel()

	err = c.Register(regCtx, srv.URL, jwk.WithWaitReady(true))
	fmt.Printf("registered and ready: %t\n", err == nil)
	fmt.Printf("registered but first fetch pending: %t\n", errors.Is(err, httprc.ErrNotReady()))

	// The error from `Register` does not carry the HTTP failure that caused
	// it, so read the cause from the sink. The URL below is a random
	// `httptest` address, and is rewritten to a fixed one only to keep the
	// output of this example stable.
	select {
	case fetchErr := <-fetchErrs:
		fmt.Printf("cause reported to the sink: %s\n",
			strings.ReplaceAll(fetchErr.Error(), srv.URL, `https://jwks.example/keys`))
	case <-time.After(5 * time.Second):
		fmt.Print("cause reported to the sink: none\n")
	}

	// `httprc.ErrNotReady()` is recoverable: the caller can start serving the
	// traffic that does not need the JWKS yet instead of aborting startup.
	// Until the first fetch lands, however, there is nothing to look up.
	_, err = c.Lookup(ctx, srv.URL)
	fmt.Printf("keys available while the endpoint is down: %t\n", err == nil)

	// The endpoint recovers. `Refresh` fetches immediately instead of waiting
	// for the next scheduled refresh.
	healthy.Store(true)
	set, err := c.Refresh(ctx, srv.URL)
	if err != nil {
		fmt.Printf("failed to refresh JWKS: %s\n", err)
		return
	}
	fmt.Printf("keys available after the endpoint recovers: %d\n", set.Len())

	// OUTPUT:
	// registered and ready: false
	// registered but first fetch pending: true
	// cause reported to the sink: httprc.Resource.Sync: unexpected status code (status code=500, url="https://jwks.example/keys")
	// keys available while the endpoint is down: false
	// keys available after the endpoint recovers: 1
}
