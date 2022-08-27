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

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

//nolint:revive,golint
func checkAccessCount(t *testing.T, ctx context.Context, src jwk.Set, expected ...int) bool {
	t.Helper()

	iter := src.Keys(ctx)
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

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdrs := w.Header()
			hdrs.Set(`Content-Type`, `application/json`)
			hdrs.Set(`Cache-Control`, `max-age=5`)

			json.NewEncoder(w).Encode(set)
		}))
		defer srv.Close()

		af := jwk.NewCache(ctx, jwk.WithRefreshWindow(time.Second))
		if !assert.NoError(t, af.Register(srv.URL), `af.Register should succeed`) {
			return
		}

		cached := jwk.NewCachedSet(af, srv.URL)
		if !assert.Error(t, cached.Set("bogus", nil), `cached.Set should be an error`) {
			return
		}
		if !assert.Error(t, cached.Remove("bogus"), `cached.Remove should be an error`) {
			return
		}
		if !assert.Error(t, cached.AddKey(nil), `cached.AddKey should be an error`) {
			return
		}
		if !assert.Error(t, cached.RemoveKey(nil), `cached.RemoveKey should be an error`) {
			return
		}
		if !assert.Equal(t, set.Len(), cached.Len(), `value of Len() should be the same`) {
			return
		}

		iter := set.Keys(ctx)
		citer := cached.Keys(ctx)
		for i := 0; i < numKeys; i++ {
			k, err := set.Key(i)
			ck, cerr := cached.Key(i)
			if !assert.Equal(t, k, ck, `key %d should match`, i) {
				return
			}
			if !assert.Equal(t, err, cerr, `error %d should match`, i) {
				return
			}

			if !assert.Equal(t, iter.Next(ctx), citer.Next(ctx), `iter.Next should match`) {
				return
			}

			if !assert.Equal(t, iter.Pair(), citer.Pair(), `iter.Pair should match`) {
				return
			}
		}
	})
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

		af := jwk.NewCache(ctx, jwk.WithRefreshWindow(time.Second))
		if !assert.NoError(t, af.Register(srv.URL, jwk.WithRefreshInterval(3*time.Second)), `af.Register should succeed`) {
			return
		}

		retries := 5

		var wg sync.WaitGroup
		wg.Add(retries)
		for i := 0; i < retries; i++ {
			// Run these in separate goroutines to emulate a possible thundering herd
			go func() {
				defer wg.Done()
				ks, err := af.Get(ctx, srv.URL)
				if !assert.NoError(t, err, `af.Get should succeed`) {
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
		ks, err := af.Get(ctx, srv.URL)
		if !assert.NoError(t, err, `af.Get should succeed`) {
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

		af := jwk.NewCache(ctx, jwk.WithRefreshWindow(time.Second))
		if !assert.NoError(t, af.Register(srv.URL, jwk.WithMinRefreshInterval(time.Second)), `af.Register should succeed`) {
			return
		}

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
				ks, err := af.Get(ctx, srv.URL)
				if !assert.NoError(t, err, `af.Get should succeed`) {
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
		ks, err := af.Get(ctx, srv.URL)
		if !assert.NoError(t, err, `af.Get should succeed`) {
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

		af := jwk.NewCache(ctx, jwk.WithRefreshWindow(time.Second))
		af.Register(srv.URL, jwk.WithMinRefreshInterval(time.Second))

		// First fetch should succeed
		ks, err := af.Get(ctx, srv.URL)
		if !assert.NoError(t, err, `af.Get (#1) should succeed`) {
			return
		}
		if !checkAccessCount(t, ctx, ks, 1) {
			return
		}

		// enough time for 1 refresh to have occurred
		time.Sleep(1500 * time.Millisecond)
		ks, err = af.Get(ctx, srv.URL)
		if !assert.NoError(t, err, `af.Get (#2) should succeed`) {
			return
		}
		// Should be using the cached version
		if !checkAccessCount(t, ctx, ks, 1) {
			return
		}

		// enough time for 2 refreshes to have occurred
		time.Sleep(2500 * time.Millisecond)

		ks, err = af.Get(ctx, srv.URL)
		if !assert.NoError(t, err, `af.Get (#3) should succeed`) {
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

	ar := jwk.NewCache(ctx, jwk.WithRefreshWindow(time.Second))
	for _, url := range jwksURLs {
		if !assert.NoError(t, ar.Register(url), `ar.Register should succeed`) {
			return
		}
	}

	for _, url := range jwksURLs {
		_ = ar.Unregister(url)
	}

	for _, target := range ar.Snapshot().Entries {
		t.Logf("%s last refreshed at %s", target.URL, target.LastFetched)
	}

	for _, url := range jwksURLs {
		ar.Unregister(url)
	}

	if !assert.Len(t, ar.Snapshot().Entries, 0, `there should be no URLs`) {
		return
	}

	if !assert.Error(t, ar.Unregister(`dummy`), `removing a non-existing url should be an error`) {
		return
	}
}

type accumulateErrs struct {
	mu   sync.RWMutex
	errs []error
}

func (e *accumulateErrs) Error(err error) {
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
		Options func() []jwk.RegisterOption
		Handler http.Handler
	}{
		/*
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
		*/
		{
			Name: `rejected by whitelist`,
			Options: func() []jwk.RegisterOption {
				return []jwk.RegisterOption{
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

			var errSink accumulateErrs
			ar := jwk.NewCache(ctx, jwk.WithErrSink(&errSink), jwk.WithRefreshWindow(time.Second))

			var options []jwk.RegisterOption
			if f := tc.Options; f != nil {
				options = f()
			}
			options = append(options, jwk.WithRefreshInterval(time.Second))
			if !assert.NoError(t, ar.Register(srv.URL, options...), `ar.Register should succeed`) {
				return
			}

			_, _ = ar.Get(ctx, srv.URL)

			timer := time.NewTimer(6 * time.Second)

			select {
			case <-ctx.Done():
				t.Errorf(`ctx.Done before timer`)
			case <-timer.C:
			}

			cancel() // forcefully end context, and thus the Cache

			// timing issues can cause this to be non-deterministic...
			// we'll say it's okay as long as we're in +/- 1 range
			l := errSink.Len()
			if !assert.True(t, l <= 7, "number of errors shold be less than or equal to 7 (%d)", l) {
				return
			}
			if !assert.True(t, l >= 5, "number of errors shold be greather than or equal to 5 (%d)", l) {
				return
			}
		})
	}
}

func TestPostFetch(t *testing.T) {
	t.Parallel()

	set := jwk.NewSet()
	for i := 0; i < 3; i++ {
		key, err := jwk.FromRaw([]byte(fmt.Sprintf(`abracadabra-%d`, i)))
		if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
			return
		}
		_ = set.AddKey(key)
	}

	testcases := []struct {
		Name      string
		Options   []jwk.RegisterOption
		ExpectKid bool
	}{
		{
			Name: "No PostFetch",
		},
		{
			Name: "With PostFetch",
			Options: []jwk.RegisterOption{jwk.WithPostFetcher(jwk.PostFetchFunc(func(_ string, set jwk.Set) (jwk.Set, error) {
				for i := 0; i < set.Len(); i++ {
					key, _ := set.Key(i)
					key.Set(jwk.KeyIDKey, fmt.Sprintf(`key-%d`, i))
				}
				return set, nil
			}))},
			ExpectKid: true,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(set)
			}))
			defer srv.Close()

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			ar := jwk.NewCache(ctx)

			ar.Register(srv.URL, tc.Options...)
			set, err := ar.Get(ctx, srv.URL)
			if !assert.NoError(t, err, `ar.Fetch should succeed`) {
				return
			}

			for i := 0; i < set.Len(); i++ {
				key, _ := set.Key(i)
				if tc.ExpectKid {
					if !assert.NotEmpty(t, key.KeyID(), `key.KeyID should not be empty`) {
						return
					}
				} else {
					if !assert.Empty(t, key.KeyID(), `key.KeyID should be empty`) {
						return
					}
				}
			}
		})
	}
}
