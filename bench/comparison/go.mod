module github.com/lestrrat-go/jwx/bench/comparison

go 1.15

replace github.com/lestrrat-go/jwx => ../..

require (
	github.com/golang-jwt/jwt/v4 v4.2.0
	github.com/lestrrat-go/jwx v1.2.5
	github.com/stretchr/testify v1.7.0
)
