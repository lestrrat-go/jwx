module github.com/lestrrat-go/jwx/bench/comparison

go 1.15

replace github.com/lestrrat-go/jwx => ../..

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/lestrrat-go/jwx v1.2.5
	github.com/stretchr/testify v1.7.0
)
