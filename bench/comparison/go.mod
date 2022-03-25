module github.com/lestrrat-go/jwx/v2/bench/comparison

go 1.15

replace github.com/lestrrat-go/jwx/v2 => ../..

require (
	github.com/golang-jwt/jwt/v4 v4.4.0
	github.com/lestrrat-go/jwx/v2 v2.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.7.1
)
