module github.com/lestrrat-go/jwx

go 1.15

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.1.0
	github.com/goccy/go-json v0.9.10
	github.com/lestrrat-go/backoff/v2 v2.0.8
	github.com/lestrrat-go/blackmagic v1.0.1
	github.com/lestrrat-go/httpcc v1.0.1
	github.com/lestrrat-go/iter v1.0.2
	github.com/lestrrat-go/option v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.0
	golang.org/x/crypto v0.0.0-20220427172511-eb4f295cb31f
)

retract v1.2.16 // Packaging problems.
