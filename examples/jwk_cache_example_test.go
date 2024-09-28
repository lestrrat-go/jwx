package examples_test

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func ExampleJWK_Cache() {
	ctx, cancel := context.WithCancel(context.Background())

	const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

	// First, set up the `jwk.Cache` object. You need to pass it a
	// `context.Context` object to control the lifecycle of the background fetching goroutine.
	c, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		fmt.Printf("failed to create cache: %s\n", err)
		return
	}

	// Tell *jwk.Cache that we only want to refresh this JWKS periodically.
	if err := c.Register(ctx, googleCerts); err != nil {
		fmt.Printf("failed to register google JWKS: %s\n", err)
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
		keyset, err := c.Lookup(ctx, googleCerts)
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
		// If refetching the keyset fails, a cached version will be returned from the previous successful
		// fetch upon calling `(jwk.Cache).Fetch()`.

		// Do interesting stuff with the keyset... but here, we just
		// sleep for a bit
		time.Sleep(time.Second)

		// Because we're a dummy program, we just cancel the loop now.
		// If this were a real program, you presumably loop forever
		cancel()
	}
	// OUTPUT:
}
