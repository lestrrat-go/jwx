package jwk_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

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
				ks, err := af.Fetch(ctx, srv.URL)
				if !assert.NoError(t, err, `af.Fetch should succeed`) {
					return
				}

				for iter := ks.Iterate(ctx); iter.Next(ctx); {
					key := iter.Pair().Value.(jwk.Key)
					v, ok := key.Get(`accessCount`)
					if !assert.True(t, ok, `key.Get("accessCount") should succeed`) {
						return
					}

					if !assert.Equal(t, float64(1), v, `key.Get("accessCount") should be 1`) {
						return
					}
				}
				wg.Done()
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
		for iter := ks.Iterate(ctx); iter.Next(ctx); {
			key := iter.Pair().Value.(jwk.Key)
			v, ok := key.Get(`accessCount`)
			if !assert.True(t, ok, `key.Get("accessCount") should succeed`) {
				return
			}

			if !assert.Equal(t, float64(2), v, `key.Get("accessCount") should be 2`) {
				return
			}
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
				ks, err := af.Fetch(ctx, srv.URL)
				if !assert.NoError(t, err, `af.Fetch should succeed`) {
					return
				}

				for iter := ks.Iterate(ctx); iter.Next(ctx); {
					key := iter.Pair().Value.(jwk.Key)
					v, ok := key.Get(`accessCount`)
					if !assert.True(t, ok, `key.Get("accessCount") should succeed`) {
						return
					}

					if !assert.Equal(t, float64(1), v, `key.Get("accessCount") should be 1`) {
						return
					}
				}
				wg.Done()
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
		for iter := ks.Iterate(ctx); iter.Next(ctx); {
			key := iter.Pair().Value.(jwk.Key)
			v, ok := key.Get(`accessCount`)
			if !assert.True(t, ok, `key.Get("accessCount") should succeed`) {
				return
			}

			if !assert.Equal(t, float64(2), v, `key.Get("accessCount") should be 2`) {
				return
			}
		}
	})
}
