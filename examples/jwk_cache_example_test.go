package examples_test

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_Cache() {
	ctx, cancel := context.WithCancel(context.Background())

	const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

	// First, set up the `jwk.Cache` object. You need to pass it a
	// `context.Context` object to control the lifecycle of the background fetching goroutine.
	//
	// Note that by default refreshes only happen very 15 minutes at the
	// earliest. If you need to control this, use `jwk.WithRefreshWindow()`
	c := jwk.NewCache(ctx)

	// Tell *jwk.Cache that we only want to refresh this JWKS
	// when it needs to (based on Cache-Control or Expires header from
	// the HTTP response). If the calculated minimum refresh interval is less
	// than 15 minutes, don't go refreshing any earlier than 15 minutes.
	c.Register(googleCerts, jwk.WithMinRefreshInterval(15*time.Minute))

	// Refresh the JWKS once before getting into the main loop.
	// This allows you to check if the JWKS is available before we start
	// a long-running program
	_, err := c.Refresh(ctx, googleCerts)
	if err != nil {
		fmt.Printf("failed to refresh google JWKS: %s\n", err)
		return
	}

	// Pretend that this is your program's main loop
MAIN:
	for {
		select {
		case <-ctx.Done():
			break MAIN
		default:
		}
		keyset, err := c.Get(ctx, googleCerts)
		if err != nil {
			fmt.Printf("failed to fetch google JWKS: %s\n", err)
			return
		}
		_ = keyset
		// The returned `keyset` will always be "reasonably" new.
		//
		// By "reasonably" we mean that we cannot guarantee that the keys will be refreshed
		// immediately after it has been rotated in the remote source. But it should be close\
		// enough, and should you need to forcefully refresh the token using the `(jwk.Cache).Refresh()` method.
		//
		// If re-fetching the keyset fails, a cached version will be returned from the previous successful
		// fetch upon calling `(jwk.Cache).Fetch()`.

		// Do interesting stuff with the keyset... but here, we just
		// sleep for a bit
		time.Sleep(time.Second)

		// Because we're a dummy program, we just cancel the loop now.
		// If this were a real program, you prosumably loop forever
		cancel()
	}
	// OUTPUT:
}
