module github.com/lestrrat-go/jwx/v3/examples

go 1.16

require (
	github.com/cloudflare/circl v1.3.7
	github.com/lestrrat-go/jwx/v3 v3.0.0
)

replace github.com/cloudflare/circl v1.0.0 => github.com/cloudflare/circl v1.0.1-0.20210104183656-96a0695de3c3

replace github.com/lestrrat-go/jwx/v3 v3.0.0 => ../
