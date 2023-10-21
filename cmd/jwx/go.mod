module github.com/lestrrat-go/jwx/v3/cmd/jwx

go 1.20

require (
	github.com/lestrrat-go/jwx/v3 v3.0.0
	github.com/urfave/cli/v2 v2.26.0
	golang.org/x/crypto v0.26.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/xrash/smetrics v0.0.0-20231213231151-1d8dd44e695e // indirect
	golang.org/x/sys v0.23.0 // indirect
)

replace github.com/lestrrat-go/jwx/v3 v3.0.0 => ../..
