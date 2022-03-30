module github.com/lestrrat-go/jwx/bench/comparison

go 1.15

replace github.com/lestrrat-go/jwx => ../..

require (
	github.com/golang-jwt/jwt/v4 v4.4.1
	github.com/lestrrat-go/jwx/v2 v2.0.0-20220329235520-6a0452901a57
	github.com/stretchr/testify v1.7.1
)
