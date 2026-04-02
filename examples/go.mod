module github.com/lestrrat-go/jwx/v3/examples

go 1.25.0

require (
	github.com/cloudflare/circl v1.6.3
	github.com/emmansun/gmsm v0.41.1
	github.com/lestrrat-go/httprc/v3 v3.0.5
	github.com/lestrrat-go/jwx-circl-ed448 v0.0.0
	github.com/lestrrat-go/jwx/v3 v3.0.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.0.1-0.20260402074825-c0d43bb43299 // indirect
	github.com/lestrrat-go/dsig-circl-ed448 v0.0.0-20260402082439-9eb97b3a7f2e // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/cloudflare/circl v1.0.0 => github.com/cloudflare/circl v1.0.1-0.20210104183656-96a0695de3c3

replace github.com/lestrrat-go/jwx/v3 v3.0.0 => ../
