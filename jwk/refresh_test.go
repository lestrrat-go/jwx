package jwk_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestAutoRefresh(t *testing.T) {
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
		hdrs.Set(`Cache-Control`, `max-age=1`)

		json.NewEncoder(w).Encode(key)
	}))

	af := jwk.NewAutoRefresh(ctx)

	retries := 5
	for i := 0; i < retries; i++ {
		ks, err := af.Fetch(ctx, srv.URL, jwk.WithRefreshInterval(3*time.Second))
		if !assert.NoError(t, err, `af.Fetch should succeed`) {
			return
		}

		for iter := ks.Iterate(ctx); iter.Next(ctx); {
			key := iter.Pair().Value.(jwk.Key)
			v, ok := key.Get(`accessCount`)
			if !assert.True(t, ok, `key.Get("accessCount") should succeed`) {
				return
			}

			if !assert.Equal(t, v, float64(1), `key.Get("accessCount") should be 1`) {
				return
			}
		}
	}

	t.Logf("Waiting for the refresh ...")
	time.Sleep(6 * time.Second)
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

		if !assert.Equal(t, v, float64(2), `key.Get("accessCount") should be 2`) {
			return
		}
	}
}
