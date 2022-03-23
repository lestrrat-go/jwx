module github.com/lestrrat-go/jwx/v2

go 1.15

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/goccy/go-json v0.9.5
	github.com/jwx-go/jwkfetch v0.0.0-20220323025228-814a17bbdf8f
	github.com/lestrrat-go/backoff/v2 v2.0.8
	github.com/lestrrat-go/blackmagic v1.0.0
	github.com/lestrrat-go/httprc v0.0.0-20220323101112-f6e42182c21c
	github.com/lestrrat-go/iter v1.0.1
	github.com/lestrrat-go/option v1.0.0
	github.com/stretchr/testify v1.7.1
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292
)

replace github.com/lestrrat-go/httprc => ../httprc

replace github.com/lestrrat-go/option => ../option
