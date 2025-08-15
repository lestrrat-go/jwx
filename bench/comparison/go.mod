module github.com/lestrrat-go/jwx/bench/comparison

go 1.24.4

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/lestrrat-go/jwx/v3 v3.0.3
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v0.0.0-20250815061604-76113d026db6 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v0.0.0-20250815041810-c96ee2d41f5e // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.0 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

replace github.com/lestrrat-go/jwx/v3 => ../..
