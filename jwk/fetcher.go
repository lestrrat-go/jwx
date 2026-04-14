package jwk

import "context"

// Fetcher retrieves a JWK Set from a URL. The main jwx module is
// transport-agnostic: there is no concrete implementation of this
// interface in `jwk` itself. Use a companion such as
// `github.com/jwx-go/jwkfetch` to construct a concrete fetcher, or
// implement this interface directly on your own type.
//
// All transport and policy concerns (HTTP client, whitelist, body-size
// caps, caching) are the implementation's responsibility — this
// interface takes no options on purpose.
type Fetcher interface {
	Fetch(ctx context.Context, url string) (Set, error)
}
