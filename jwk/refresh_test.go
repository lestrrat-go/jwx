package jwk_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/iter/arrayiter"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:revive,golint
func checkAccessCount(t *testing.T, ctx context.Context, src arrayiter.Source, expected ...int) bool {
	t.Helper()

	iter := src.Iterate(ctx)
	iter.Next(ctx)

	key := iter.Pair().Value.(jwk.Key)
	v, ok := key.Get(`accessCount`)
	if !assert.True(t, ok, `key.Get("accessCount") should succeed`) {
		return false
	}

	for _, e := range expected {
		if v == float64(e) {
			return assert.Equal(t, float64(e), v, `key.Get("accessCount") should be %d`, e)
		}
	}

	var buf bytes.Buffer
	fmt.Fprint(&buf, "[")
	for i, e := range expected {
		fmt.Fprintf(&buf, "%d", e)
		if i < len(expected)-1 {
			fmt.Fprint(&buf, ", ")
		}
	}
	fmt.Fprintf(&buf, "]")
	return assert.Failf(t, `key.Get("accessCount") should be one of %s (got %d)`, buf.String(), v)
}

func TestAutoRefresh(t *testing.T) {
	t.Parallel()

	t.Run("Specify explicit refresh interval", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		var accessCount int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessCount++

			key := map[string]interface{}{
				"kty":         "EC",
				"crv":         "P-256",
				"x":           "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
				"y":           "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
				"accessCount": accessCount,
			}
			hdrs := w.Header()
			hdrs.Set(`Content-Type`, `application/json`)
			hdrs.Set(`Cache-Control`, `max-age=7200`) // Make sure this is ignored

			json.NewEncoder(w).Encode(key)
		}))
		defer srv.Close()

		af := jwk.NewAutoRefresh(ctx)
		af.Configure(srv.URL, jwk.WithRefreshInterval(3*time.Second))

		retries := 5

		var wg sync.WaitGroup
		wg.Add(retries)
		for i := 0; i < retries; i++ {
			// Run these in separate goroutines to emulate a possible thundering herd
			go func() {
				defer wg.Done()
				ks, err := af.Fetch(ctx, srv.URL)
				if !assert.NoError(t, err, `af.Fetch should succeed`) {
					return
				}
				if !checkAccessCount(t, ctx, ks, 1) {
					return
				}
			}()
		}

		t.Logf("Waiting for fetching goroutines...")
		wg.Wait()
		t.Logf("Waiting for the refresh ...")
		time.Sleep(4 * time.Second)
		ks, err := af.Fetch(ctx, srv.URL)
		if !assert.NoError(t, err, `af.Fetch should succeed`) {
			return
		}
		if !checkAccessCount(t, ctx, ks, 2) {
			return
		}
	})
	t.Run("Calculate next refresh from Cache-Control header", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		var accessCount int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessCount++

			key := map[string]interface{}{
				"kty":         "EC",
				"crv":         "P-256",
				"x":           "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
				"y":           "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
				"accessCount": accessCount,
			}
			hdrs := w.Header()
			hdrs.Set(`Content-Type`, `application/json`)
			hdrs.Set(`Cache-Control`, `max-age=3`)

			json.NewEncoder(w).Encode(key)
		}))
		defer srv.Close()

		af := jwk.NewAutoRefresh(ctx)
		af.Configure(srv.URL, jwk.WithMinRefreshInterval(time.Second))
		if !assert.True(t, af.IsRegistered(srv.URL), `af.IsRegistered should be true`) {
			return
		}

		retries := 5

		var wg sync.WaitGroup
		wg.Add(retries)
		for i := 0; i < retries; i++ {
			// Run these in separate goroutines to emulate a possible thundering herd
			go func() {
				defer wg.Done()
				ks, err := af.Fetch(ctx, srv.URL)
				if !assert.NoError(t, err, `af.Fetch should succeed`) {
					return
				}

				if !checkAccessCount(t, ctx, ks, 1) {
					return
				}
			}()
		}

		t.Logf("Waiting for fetching goroutines...")
		wg.Wait()
		t.Logf("Waiting for the refresh ...")
		time.Sleep(4 * time.Second)
		ks, err := af.Fetch(ctx, srv.URL)
		if !assert.NoError(t, err, `af.Fetch should succeed`) {
			return
		}
		if !checkAccessCount(t, ctx, ks, 2) {
			return
		}
	})
	t.Run("Backoff", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		var accessCount int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessCount++
			if accessCount > 1 && accessCount < 4 {
				http.Error(w, "wait for it....", http.StatusForbidden)
				return
			}

			key := map[string]interface{}{
				"kty":         "EC",
				"crv":         "P-256",
				"x":           "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
				"y":           "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
				"accessCount": accessCount,
			}
			hdrs := w.Header()
			hdrs.Set(`Content-Type`, `application/json`)
			hdrs.Set(`Cache-Control`, `max-age=1`)

			json.NewEncoder(w).Encode(key)
		}))
		defer srv.Close()

		af := jwk.NewAutoRefresh(ctx)
		bo := backoff.Constant(backoff.WithInterval(time.Second))
		af.Configure(srv.URL, jwk.WithFetchBackoff(bo), jwk.WithMinRefreshInterval(1))

		// First fetch should succeed
		ks, err := af.Fetch(ctx, srv.URL)
		if !assert.NoError(t, err, `af.Fetch (#1) should succed`) {
			return
		}
		if !checkAccessCount(t, ctx, ks, 1) {
			return
		}

		// enough time for 1 refresh to have occurred
		time.Sleep(1500 * time.Millisecond)
		ks, err = af.Fetch(ctx, srv.URL)
		if !assert.NoError(t, err, `af.Fetch (#2) should succeed`) {
			return
		}
		// Should be using the cached version
		if !checkAccessCount(t, ctx, ks, 1) {
			return
		}

		// enough time for 2 refreshes to have occurred
		time.Sleep(2500 * time.Millisecond)

		ks, err = af.Fetch(ctx, srv.URL)
		if !assert.NoError(t, err, `af.Fetch (#3) should succeed`) {
			return
		}
		// should be new
		if !checkAccessCount(t, ctx, ks, 4, 5) {
			return
		}
	})
}

func TestRefreshSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var jwksURLs []string
	getJwksURL := func(dst *[]string, url string) bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		defer res.Body.Close()

		var m map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
			return false
		}

		jwksURL, ok := m["jwks_uri"]
		if !ok {
			return false
		}
		*dst = append(*dst, jwksURL.(string))
		return true
	}
	if !getJwksURL(&jwksURLs, "https://oidc-sample.onelogin.com/oidc/2/.well-known/openid-configuration") {
		t.SkipNow()
	}
	if !getJwksURL(&jwksURLs, "https://accounts.google.com/.well-known/openid-configuration") {
		t.SkipNow()
	}

	ar := jwk.NewAutoRefresh(ctx)
	for _, url := range jwksURLs {
		ar.Configure(url)
	}

	for _, url := range jwksURLs {
		_, _ = ar.Refresh(ctx, url)
	}

	for target := range ar.Snapshot() {
		t.Logf("%s last refreshed at %s, next refresh at %s", target.URL, target.LastRefresh, target.NextRefresh)
	}

	for _, url := range jwksURLs {
		ar.Remove(url)
	}

	if !assert.Len(t, ar.Snapshot(), 0, `there should be no URLs`) {
		return
	}

	if !assert.Error(t, ar.Remove(`dummy`), `removing a non-existing url should be an error`) {
		return
	}
}

func TestErrorSink(t *testing.T) {
	t.Parallel()

	k, err := jwxtest.GenerateRsaJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`) {
		return
	}
	set := jwk.NewSet()
	set.Add(k)
	testcases := []struct {
		Name    string
		Options func() []jwk.AutoRefreshOption
		Handler http.Handler
	}{
		{
			Name: "non-200 response",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			}),
		},
		{
			Name: "invalid JWK",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"empty": "nonthingness"}`))
			}),
		},
		{
			Name: `rejected by whitelist`,
			Options: func() []jwk.AutoRefreshOption {
				return []jwk.AutoRefreshOption{
					jwk.WithFetchWhitelist(jwk.WhitelistFunc(func(_ string) bool {
						return false
					})),
				}
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(k)
			}),
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			srv := httptest.NewServer(tc.Handler)
			defer srv.Close()

			ar := jwk.NewAutoRefresh(ctx)

			var options []jwk.AutoRefreshOption
			if f := tc.Options; f != nil {
				options = f()
			}
			options = append(options, jwk.WithRefreshInterval(500*time.Millisecond))
			ar.Configure(srv.URL, options...)
			ch := make(chan jwk.AutoRefreshError, 256) // big buffer
			ar.ErrorSink(ch)
			ar.Fetch(ctx, srv.URL)

			timer := time.NewTimer(3 * time.Second)

			select {
			case <-ctx.Done():
				t.Errorf(`ctx.Done before timer`)
			case <-timer.C:
			}

			cancel() // forcefully end context, and thus the AutoRefresh

			// timing issues can cause this to be non-deterministic...
			// we'll say it's okay as long as we're in +/- 1 range
			l := len(ch)
			if !assert.True(t, l <= 7, "number of errors shold be less than or equal to 7 (%d)", l) {
				return
			}
			if !assert.True(t, l >= 5, "number of errors shold be greather than or equal to 5 (%d)", l) {
				return
			}
		})
	}
}

func TestAutoRefreshRace(t *testing.T) {
	k, err := jwxtest.GenerateRsaJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`) {
		return
	}
	set := jwk.NewSet()
	set.Add(k)

	// set up a server that always success since we need to update the registered target
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(k)
	}))
	defer srv.Close()

	// configure a unique auto-refresh
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ar := jwk.NewAutoRefresh(ctx)
	ch := make(chan jwk.AutoRefreshError, 256) // big buffer
	ar.ErrorSink(ch)

	wg := sync.WaitGroup{}
	routineErr := make(chan error, 20)

	// execute a bunch of parallel refresh forcing the requests to the server
	// need to simulate configure happening also in the goroutine since this is
	// the cause of races when refresh is updating the registered targets
	for i := 0; i < 5000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()

			ar.Configure(srv.URL, jwk.WithRefreshInterval(500*time.Millisecond))
			_, err := ar.Refresh(ctx, srv.URL)

			if err != nil {
				routineErr <- err
			}
		}()
	}
	wg.Wait()

	require.Len(t, routineErr, 0)
}
