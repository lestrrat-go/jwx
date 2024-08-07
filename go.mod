module github.com/lestrrat-go/jwx

go 1.20

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0
	github.com/goccy/go-json v0.10.3
	github.com/lestrrat-go/backoff/v2 v2.0.8
	github.com/lestrrat-go/blackmagic v1.0.2
	github.com/lestrrat-go/httpcc v1.0.1
	github.com/lestrrat-go/iter v1.0.2
	github.com/lestrrat-go/option v1.0.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.26.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract v1.2.16 // Packaging problems.
