module github.com/jwx-go/es256k

go 1.26.0

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0
	github.com/lestrrat-go/jwx/v3 v3.0.0
)

require (
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.1.0 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
)

replace github.com/lestrrat-go/jwx/v3 => ../../
