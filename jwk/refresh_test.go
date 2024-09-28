package jwk_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/httprc/v3/tracesink"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkAccessCount(t *testing.T, src jwk.Set, expected ...int) bool {
	t.Helper()

	key, ok := src.Key(0)
	require.True(t, ok, `src.Key(0) should succeed`)

	var v float64
	require.NoError(t, key.Get(`accessCount`, &v), `key.Get("accessCount") should succeed`)

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
	return assert.Failf(t, `checking access count failed`, `key.Get("accessCount") should be one of %s (got %f)`, buf.String(), v)
}

func TestCache(t *testing.T) {
	t.Parallel()

	t.Run("CachedSet", func(t *testing.T) {
		const numKeys = 3
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		set := jwk.NewSet()
		for i := 0; i < numKeys; i++ {
			key, err := jwxtest.GenerateRsaJwk()
			if !assert.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`) {
				return
			}
			if !assert.NoError(t, set.AddKey(key), `set.AddKey should succeed`) {
				return
			}
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hdrs := w.Header()
			hdrs.Set(`Content-Type`, `application/json`)
			hdrs.Set(`Cache-Control`, `max-age=5`)

			json.NewEncoder(w).Encode(set)
		}))
		defer srv.Close()

		c, err := jwk.NewCache(ctx, httprc.NewClient())
		require.NoError(t, err, `jwk.NewCache should succeed`)
		require.NoError(t, c.Register(ctx, srv.URL), `af.Register should succeed`)

		cs, err := c.CachedSet(srv.URL)
		require.NoError(t, err, `c.CachedSet should succeed`)
		require.Error(t, cs.Set("bogus", nil), `cs.Set should be an error`)
		require.Error(t, cs.Remove("bogus"), `cs.Remove should be an error`)
		require.Error(t, cs.AddKey(nil), `cs.AddKey should be an error`)
		require.Error(t, cs.RemoveKey(nil), `cs.RemoveKey should be an error`)
		require.Equal(t, set.Len(), cs.Len(), `value of Len() should be the same`)

		for i := 0; i < set.Len(); i++ {
			k, err := set.Key(i)
			ck, cerr := cs.Key(i)
			if !assert.Equal(t, k, ck, `key %d should match`, i) {
				return
			}
			if !assert.Equal(t, err, cerr, `error %d should match`, i) {
				return
			}
		}
	})
	t.Run("Specify explicit refresh interval", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		var accessCount int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

		c, err := jwk.NewCache(ctx, httprc.NewClient(
		//			httprc.WithTraceSink(tracesink.NewSlog(slog.New(slog.NewJSONHandler(os.Stdout, nil)))),
		))
		require.NoError(t, err, `jwk.NewCache should succeed`)
		require.NoError(t, c.Register(ctx, srv.URL, jwk.WithConstantInterval(2*time.Second+500*time.Millisecond)), `c.Register should succeed`)
		require.True(t, c.Ready(ctx, srv.URL), `c.Ready should be true`)

		retries := 5

		var wg sync.WaitGroup
		wg.Add(retries)
		for i := 0; i < retries; i++ {
			// Run these in separate goroutines to emulate a possible thundering herd
			go func() {
				defer wg.Done()
				ks, err := c.Lookup(ctx, srv.URL)
				require.NoError(t, err, `c.Lookup should succeed`)
				require.NotNil(t, ks, `c.Lookup should return a non-nil key set`)
				if !checkAccessCount(t, ks, 1) {
					return
				}
			}()
		}

		t.Logf("Waiting for fetching goroutines...")
		wg.Wait()
		t.Logf("Waiting for the refresh ...")
		time.Sleep(6 * time.Second)
		ks, err := c.Lookup(ctx, srv.URL)
		require.NoError(t, err, `c.Lookup should succeed`)

		if !checkAccessCount(t, ks, 2) {
			return
		}
	})
	t.Run("Calculate next refresh from Cache-Control header", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		var accessCount int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

		c, err := jwk.NewCache(ctx, httprc.NewClient(
		//			httprc.WithTraceSink(tracesink.NewSlog(slog.New(slog.NewJSONHandler(os.Stdout, nil)))),
		))
		require.NoError(t, err, `jwk.NewCache should succeed`)
		require.NoError(t, c.Register(ctx, srv.URL), `c.Register should succeed`)
		require.True(t, c.IsRegistered(ctx, srv.URL), `c.IsRegistered should be true`)
		require.True(t, c.Ready(ctx, srv.URL), `c.Ready should be true`)

		retries := 5

		var wg sync.WaitGroup
		wg.Add(retries)
		for i := 0; i < retries; i++ {
			// Run these in separate goroutines to emulate a possible thundering herd
			go func() {
				defer wg.Done()
				ks, err := c.Lookup(ctx, srv.URL)
				require.NoError(t, err, `c.Lookup should succeed`)
				require.NotNil(t, ks, `c.Lookup should return a non-nil key set`)
				if !checkAccessCount(t, ks, 1) {
					return
				}
			}()
		}

		t.Logf("Waiting for fetching goroutines...")
		wg.Wait()
		t.Logf("Waiting for the refresh ...")
		time.Sleep(4 * time.Second)
		ks, err := c.Lookup(ctx, srv.URL)
		require.NoError(t, err, `c.Lookup should succeed`)
		if !checkAccessCount(t, ks, 2) {
			return
		}
	})
	t.Run("Backoff", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		var accessCount int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hdrs := w.Header()
			hdrs.Set(`Cache-Control`, `max-age=1`)
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
			hdrs.Set(`Content-Type`, `application/json`)

			json.NewEncoder(w).Encode(key)
		}))
		defer srv.Close()

		c, err := jwk.NewCache(ctx, httprc.NewClient(
			httprc.WithTraceSink(tracesink.NewSlog(slog.New(slog.NewJSONHandler(os.Stdout, nil)))),
		))
		require.NoError(t, err, `jwk.NewCache should succeed`)
		require.NoError(t, c.Register(ctx, srv.URL, jwk.WithMinRefreshInterval(time.Second)), `c.Register should succeed`)
		require.True(t, c.Ready(ctx, srv.URL), `c.Ready should be true`)

		// First fetch should succeed
		ks, err := c.Lookup(ctx, srv.URL)
		require.NoError(t, err, `c.Lookup (#1) should succeed`)
		require.NotNil(t, ks, `c.Lookup (#1) should return a non-nil key set`)
		if !checkAccessCount(t, ks, 1) {
			return
		}

		// enough time for 1 refresh to have occurred
		time.Sleep(1500 * time.Millisecond)
		ks, err = c.Lookup(ctx, srv.URL)
		require.NoError(t, err, `c.Lookup (#2) should succeed`)
		require.NotNil(t, ks, `c.Lookup (#2) should return a non-nil key set`)
		// Should be using the cached version
		if !checkAccessCount(t, ks, 1) {
			return
		}

		// enough time for 2 refreshes to have occurred
		time.Sleep(2500 * time.Millisecond)

		ks, err = c.Lookup(ctx, srv.URL)
		require.NoError(t, err, `c.Lookup (#3) should succeed`)
		require.NotNil(t, ks, `c.Lookup (#3) should return a non-nil key set`)
		// should be new
		if !checkAccessCount(t, ks, 4, 5) {
			return
		}
	})
}

type accumulateErrs struct {
	mu   sync.RWMutex
	errs []error
}

func (e *accumulateErrs) Put(_ context.Context, err error) {
	e.mu.Lock()
	e.errs = append(e.errs, err)
	e.mu.Unlock()
}

func (e *accumulateErrs) Len() int {
	e.mu.RLock()
	l := len(e.errs)
	e.mu.RUnlock()
	return l
}
func TestErrorSink(t *testing.T) {
	t.Parallel()

	k, err := jwxtest.GenerateRsaJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`) {
		return
	}
	set := jwk.NewSet()
	_ = set.AddKey(k)
	testcases := []struct {
		Name    string
		Options func() []httprc.NewClientOption
		Handler http.Handler
	}{
		{
			Name: `rejected by whitelist`,
			Options: func() []httprc.NewClientOption {
				return []httprc.NewClientOption{
					httprc.WithWhitelist(httprc.NewBlockAllWhitelist()),
				}
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

			var errSink accumulateErrs
			options := append(tc.Options(), httprc.WithErrorSink(&errSink))
			c, err := jwk.NewCache(ctx, httprc.NewClient(options...))
			require.NoError(t, err, `jwk.NewCache should succeed`)
			require.Error(t, c.Register(ctx, srv.URL), `c.Register should fail`)
		})
	}
}
