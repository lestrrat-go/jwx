package examples_test

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func ExampleJWK_CachedSet() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

	// The first steps are the same as examples/jwk_cache_example_test.go
	c, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		fmt.Printf("failed to create cache: %s\n", err)
		return
	}

	if err := c.Register(ctx, googleCerts, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
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
}
