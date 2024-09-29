module github.com/lestrrat-go/jwx/v3/examples

go 1.22.6

require (
	github.com/cloudflare/circl v1.3.7
	github.com/emmansun/gmsm v0.21.5
	github.com/lestrrat-go/httprc/v3 v3.0.0-alpha1.0.20240929065954-2edd851292b5
	github.com/lestrrat-go/jwx/v3 v3.0.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/cloudflare/circl v1.0.0 => github.com/cloudflare/circl v1.0.1-0.20210104183656-96a0695de3c3

replace github.com/lestrrat-go/jwx/v3 v3.0.0 => ../
