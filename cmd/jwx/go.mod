module github.com/lestrrat-go/jwx/v2/cmd/jwx

go 1.17

require (
	github.com/lestrrat-go/jwx/v2 v2.0.0-00010101000000-000000000000
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/crypto v0.0.0-20220427172511-eb4f295cb31f
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/goccy/go-json v0.9.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.1 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.2 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
)

replace github.com/lestrrat-go/jwx/v2 => ../..
