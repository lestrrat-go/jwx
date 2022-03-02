module github.com/lestrrat-go/jwx/v2/bench/comparison

go 1.15

replace github.com/lestrrat-go/jwx/v2 => ../..

require (
	github.com/golang-jwt/jwt/v4 v4.2.0
	github.com/lestrrat-go/jwx/v2 v1.2.5
	github.com/stretchr/testify v1.7.0
)
