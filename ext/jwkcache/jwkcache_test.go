package jwkcache_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/httprc/v3/tracesink"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jwx-go/jwkcache"
)

func generateRsaJwk(t *testing.T) jwk.Key {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, `rsa.GenerateKey should succeed`)
	jwkKey, err := jwk.Import(key)
	require.NoError(t, err, `jwk.Import should succeed`)
	return jwkKey
}

func getAccessCount(t *testing.T, src jwk.Set) int {
	t.Helper()

	key, ok := src.Key(0)
	require.True(t, ok, `src.Key(0) should succeed`)

	var v float64
	require.NoError(t, key.Get(`accessCount`, &v), `key.Get("accessCount") should succeed`)

	return int(v)
}

func checkAccessCount(t *testing.T, src jwk.Set, expected ...int) {
	t.Helper()

	v := getAccessCount(t, src)

	for _, e := range expected {
		if v == e {
			assert.Equal(t, e, v, `key.Get("accessCount") should be %d`, e)
			return
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
	require.Failf(t, `checking access count failed`, `key.Get("accessCount") should be one of %s (got %d)`, buf.String(), v)
}

func waitForAccessCountAtLeast(ctx context.Context, t *testing.T, c *jwkcache.Cache, url string, minCount int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ks, err := c.Lookup(ctx, url)
		if err == nil {
			if v := getAccessCount(t, ks); v >= minCount {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	require.Failf(t, `timed out`, `timed out waiting for accessCount >= %d`, minCount)
}

func TestCachedSet(t *testing.T) {
	t.Parallel()
	const numKeys = 3
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	set := jwk.NewSet()
	for range numKeys {
		key := generateRsaJwk(t)
		require.NoError(t, set.AddKey(key), `set.AddKey should succeed`)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hdrs := w.Header()
		hdrs.Set(`Content-Type`, `application/json`)
		hdrs.Set(`Cache-Control`, `max-age=5`)

		jsonv2.MarshalWrite(w, set)
	}))
	defer srv.Close()

	c, err := jwkcache.NewCache(ctx, httprc.NewClient())
	require.NoError(t, err, `jwkcache.NewCache should succeed`)
	require.NoError(t, c.Register(ctx, srv.URL), `c.Register should succeed`)

	cs, err := c.CachedSet(srv.URL)
	require.NoError(t, err, `c.CachedSet should succeed`)
	require.Error(t, cs.Set("bogus", nil), `cs.Set should be an error`)
	require.Error(t, cs.Remove("bogus"), `cs.Remove should be an error`)
	require.Error(t, cs.AddKey(nil), `cs.AddKey should be an error`)
	require.Error(t, cs.RemoveKey(nil), `cs.RemoveKey should be an error`)
	require.Equal(t, set.Len(), cs.Len(), `value of Len() should be the same`)

	for i := range set.Len() {
		k, err := set.Key(i)
		ck, cerr := cs.Key(i)
		require.Equal(t, k, ck, `key %d should match`, i)
		require.Equal(t, err, cerr, `error %d should match`, i)
	}
}

func TestCache_explicit_refresh_interval(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var accessCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := accessCount.Add(1)
		key := map[string]any{
			"kty":         "EC",
			"crv":         "P-256",
			"x":           "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
			"y":           "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
			"accessCount": count,
		}
		hdrs := w.Header()
		hdrs.Set(`Content-Type`, `application/json`)
		hdrs.Set(`Cache-Control`, `max-age=7200`) // Make sure this is ignored

		jsonv2.MarshalWrite(w, key)
	}))
	defer srv.Close()

	c, err := jwkcache.NewCache(ctx, httprc.NewClient())
	require.NoError(t, err, `jwkcache.NewCache should succeed`)
	require.NoError(t, c.Register(ctx, srv.URL, jwkcache.WithConstantInterval(2*time.Second+500*time.Millisecond)), `c.Register should succeed`)

	retries := 5

	var wg sync.WaitGroup
	wg.Add(retries)
	for range retries {
		go func() {
			defer wg.Done()
			ks, err := c.Lookup(ctx, srv.URL)
			require.NoError(t, err, `c.Lookup should succeed`)
			require.NotNil(t, ks, `c.Lookup should return a non-nil key set`)
			checkAccessCount(t, ks, 1)
		}()
	}

	t.Logf("Waiting for fetching goroutines...")
	wg.Wait()
	t.Logf("Waiting for the refresh ...")

	waitForAccessCountAtLeast(ctx, t, c, srv.URL, 2, 15*time.Second)
}

func TestCache_calculate_interval_from_cache_control(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var accessCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := accessCount.Add(1)

		key := map[string]any{
			"kty":         "EC",
			"crv":         "P-256",
			"x":           "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
			"y":           "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
			"accessCount": count,
		}
		hdrs := w.Header()
		hdrs.Set(`Content-Type`, `application/json`)
		hdrs.Set(`Cache-Control`, `max-age=3`)

		jsonv2.MarshalWrite(w, key)
	}))
	defer srv.Close()

	c, err := jwkcache.NewCache(ctx, httprc.NewClient(
		httprc.WithTraceSink(tracesink.NewSlog(
			slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("test", "Cache_calculate_interval_from_cache_control"),
		)),
	))
	require.NoError(t, err, `jwkcache.NewCache should succeed`)
	require.NoError(t, c.Register(ctx, srv.URL,
		jwkcache.WithMinInterval(3*time.Second),
	), `c.Register should succeed`)
	require.True(t, c.IsRegistered(ctx, srv.URL), `c.IsRegistered should be true`)

	retries := 5

	var wg sync.WaitGroup
	wg.Add(retries)
	for range retries {
		go func() {
			defer wg.Done()
			ks, err := c.Lookup(ctx, srv.URL)
			require.NoError(t, err, `c.Lookup should succeed`)
			require.NotNil(t, ks, `c.Lookup should return a non-nil key set`)
			checkAccessCount(t, ks, 1)
		}()
	}

	t.Logf("Waiting for fetching goroutines...")
	wg.Wait()
	t.Logf("Waiting for the refresh ...")

	waitForAccessCountAtLeast(ctx, t, c, srv.URL, 2, 15*time.Second)
}

func TestCache_backoff(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var accessCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hdrs := w.Header()
		hdrs.Set(`Cache-Control`, `max-age=1`)
		count := accessCount.Add(1)
		if count > 1 && count < 4 {
			http.Error(w, "wait for it....", http.StatusForbidden)
			return
		}

		key := map[string]any{
			"kty":         "EC",
			"crv":         "P-256",
			"x":           "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
			"y":           "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
			"accessCount": count,
		}
		hdrs.Set(`Content-Type`, `application/json`)

		jsonv2.MarshalWrite(w, key)
	}))
	defer srv.Close()

	c, err := jwkcache.NewCache(ctx, httprc.NewClient(
		httprc.WithTraceSink(tracesink.NewSlog(
			slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("test", "Cache_backoff"),
		)),
	))
	require.NoError(t, err, `jwkcache.NewCache should succeed`)
	require.NoError(t, c.Register(ctx, srv.URL, jwkcache.WithMinInterval(time.Second)), `c.Register should succeed`)

	// First fetch should succeed
	ks, err := c.Lookup(ctx, srv.URL)
	require.NoError(t, err, `c.Lookup (#1) should succeed`)
	require.NotNil(t, ks, `c.Lookup (#1) should return a non-nil key set`)
	checkAccessCount(t, ks, 1)

	// Wait a bit — the next refresh(es) will fail (access 2,3 return 403),
	// so the cache should still serve the original data.
	time.Sleep(2 * time.Second)
	ks, err = c.Lookup(ctx, srv.URL)
	require.NoError(t, err, `c.Lookup (#2) should succeed`)
	require.NotNil(t, ks, `c.Lookup (#2) should return a non-nil key set`)
	checkAccessCount(t, ks, 1)

	// Poll until the server has recovered (access >= 4) and the cache
	// has been updated with the new data.
	waitForAccessCountAtLeast(ctx, t, c, srv.URL, 4, 15*time.Second)
}

func TestGH1551(t *testing.T) {
	t.Parallel()

	const numWorkers = 3

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var errSink accumulateErrs
	c, err := jwkcache.NewCache(ctx, httprc.NewClient(
		httprc.WithWorkers(numWorkers),
		httprc.WithErrorSink(&errSink),
	))
	require.NoError(t, err, `jwkcache.NewCache should succeed`)

	require.NoError(t, c.Register(ctx, srv.URL,
		jwkcache.WithWaitReady(false),
		jwkcache.WithConstantInterval(time.Hour),
	), `c.Register should succeed`)

	for i := range numWorkers {
		refreshCtx, refreshCancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := c.Refresh(refreshCtx, srv.URL)
		refreshCancel()
		require.Error(t, err, "Refresh #%d should return an error", i)
		t.Logf("Refresh #%d failed as expected: %v", i, err)
	}

	t.Log("All workers exhausted. Attempting one more Refresh()...")

	deadlockCtx, deadlockCancel := context.WithTimeout(ctx, 5*time.Second)
	defer deadlockCancel()

	_, err = c.Refresh(deadlockCtx, srv.URL)
	require.Error(t, err, "Refresh after all workers failed should still return an error")
	require.NotErrorIs(t, err, context.DeadlineExceeded,
		"Refresh should not deadlock (got context deadline exceeded, indicating workers are stuck)")
	t.Logf("Post-failure Refresh returned: %v", err)
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

	key := generateRsaJwk(t)
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
				jsonv2.MarshalWrite(w, key)
			}),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			srv := httptest.NewServer(tc.Handler)
			defer srv.Close()

			var errSink accumulateErrs
			options := append(tc.Options(), httprc.WithErrorSink(&errSink))
			c, err := jwkcache.NewCache(ctx, httprc.NewClient(options...))
			require.NoError(t, err, `jwkcache.NewCache should succeed`)
			require.Error(t, c.Register(ctx, srv.URL), `c.Register should fail`)
		})
	}
}
