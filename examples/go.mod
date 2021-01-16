module github.com/lestrrat-go/jwx/examples

go 1.16

require (
	github.com/cloudflare/circl v1.0.0
	github.com/lestrrat-go/jwx v1.0.8
	github.com/pkg/errors v0.9.1
)

replace github.com/lestrrat-go/jwx v1.0.8 => ../

replace github.com/cloudflare/circl v1.0.0 => github.com/cloudflare/circl v1.0.1-0.20210104183656-96a0695de3c3
