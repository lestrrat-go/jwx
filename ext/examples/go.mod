module github.com/lestrrat-go/jwx/v4/examples

go 1.26.0

require (
	github.com/cloudflare/circl v1.6.3
	github.com/emmansun/gmsm v0.41.1
	github.com/jwx-go/jwkcache v0.0.0
	github.com/lestrrat-go/httprc/v3 v3.0.5
	github.com/lestrrat-go/jwx/v4 v4.0.0
)

require (
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.1.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
)

replace github.com/lestrrat-go/jwx/v4 => ../../

replace github.com/jwx-go/jwkcache => ../jwkcache
