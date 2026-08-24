module github.com/lestrrat-go/jwx/bench/comparison

go 1.25.0

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/lestrrat-go/jwx/v3 v3.0.3
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/lestrrat-go/jwx/v3 => ../..
