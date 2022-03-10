package examples_test

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_AutoRefresh() {
	ctx, cancel := context.WithCancel(context.Background())

	const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

	// First, set up the `jwk.AutoRefresh` object. You need to pass it a
	// `context.Context` object to control the lifecycle of the background fetching goroutine.
	ar := jwk.NewAutoRefresh(ctx)

	// Tell *jwk.AutoRefresh that we only want to refresh this JWKS
	// when it needs to (based on Cache-Control or Expires header from
	// the HTTP response). If the calculated minimum refresh interval is less
	// than 15 minutes, don't go refreshing any earlier than 15 minutes.
	ar.Configure(googleCerts, jwk.WithMinRefreshInterval(15*time.Minute))

	// Refresh the JWKS once before getting into the main loop.
	// This allows you to check if the JWKS is available before we start
	// a long-running program
	_, err := ar.Refresh(ctx, googleCerts)
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
		keyset, err := ar.Fetch(ctx, googleCerts)
		if err != nil {
			fmt.Printf("failed to fetch google JWKS: %s\n", err)
			return
		}
		_ = keyset
		// The returned `keyset` will always be "reasonably" new. It is important that
		// you always call `ar.Fetch()` before using the `keyset` as this is where the refreshing occurs.
		//
		// By "reasonably" we mean that we cannot guarantee that the keys will be refreshed
		// immediately after it has been rotated in the remote source. But it should be close\
		// enough, and should you need to forcefully refresh the token using the `(jwk.AutoRefresh).Refresh()` method.
		//
		// If re-fetching the keyset fails, a cached version will be returned from the previous successful
		// fetch upon calling `(jwk.AutoRefresh).Fetch()`.

		// Do interesting stuff with the keyset... but here, we just
		// sleep for a bit
		time.Sleep(time.Second)

		// Because we're a dummy program, we just cancel the loop now.
		// If this were a real program, you prosumably loop forever
		cancel()
	}
	// OUTPUT:
}
