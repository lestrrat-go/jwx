package examples_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/httprc/v3/tracesink"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func ExampleJWK_CachedSet() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

	// The first steps are the same as examples/jwk_cache_example_test.go
	c, err := jwk.NewCache(
		ctx,
		httprc.NewClient(
			httprc.WithTraceSink(tracesink.NewSlog(slog.New(slog.NewJSONHandler(os.Stderr, nil)))),
		),
	)
	if err != nil {
		fmt.Printf("failed to create cache: %s\n", err)
		return
	}

	// Register the URL to fetch the JWKS from. In this case, we're saying that
	// the cache can dynamically decide how often to refresh the keyset based on
	// the HTTP headers returned by the server, but the value must be at least
	// 1 hour, and at most 7 days.
	if err := c.Register(
		ctx,
		googleCerts,
		jwk.WithMaxInterval(24*time.Hour*7),
		jwk.WithMinInterval(15*time.Minute),
	); err != nil {
		fmt.Printf("failed to register google JWKS: %s\n", err)
		return
	}

	cached, err := c.CachedSet(googleCerts)
	if err != nil {
		fmt.Printf("failed to get cached keyset: %s\n", err)
		return
	}

	// cached fulfills the jwk.Set interface.
	var _ jwk.Set = cached

	// That means you can pass it to things like jws.WithKeySet,
	// allowing you to pretend as if you are using the result of
	//
	//   jwk.Fetch(ctx, googleCerts)
	//
	// But you are instead using a cached (and periodically refreshed) set
	// for each operation.
	_ = jws.WithKeySet(cached)

	// OUTPUT:
}
