module github.com/lestrrat-go/jwx/v2/examples

go 1.15

require (
	github.com/cloudflare/circl v1.0.0
	github.com/lestrrat-go/jwx/v2 v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
)

replace github.com/lestrrat-go/jwx/v2 => ../

replace github.com/cloudflare/circl v1.0.0 => github.com/cloudflare/circl v1.0.1-0.20210104183656-96a0695de3c3
