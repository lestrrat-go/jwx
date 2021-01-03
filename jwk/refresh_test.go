package jwk_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/backoff"
	"github.com/lestrrat-go/iter/arrayiter"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

//nolint:golint
func checkAccessCount(t *testing.T, ctx context.Context, src arrayiter.Source, expected int) bool {
	t.Helper()
	for iter := src.Iterate(ctx); iter.Next(ctx); {
		key := iter.Pair().Value.(jwk.Key)
		v, ok := key.Get(`accessCount`)
		if !assert.True(t, ok, `key.Get("accessCount") should succeed`) {
			return false
		}

		if !assert.Equal(t, float64(expected), v, `key.Get("accessCount") should be %d`, expected) {
			return false
		}
	}
	return true
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
		af.Configure(srv.URL, jwk.WithRefreshBackoff(bo), jwk.WithMinRefreshInterval(1))

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
		if !checkAccessCount(t, ctx, ks, 4) {
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
}
