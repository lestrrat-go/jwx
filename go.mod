module github.com/lestrrat-go/jwx/v3

go 1.25.0

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/goccy/go-json v0.10.6
	github.com/lestrrat-go/blackmagic v1.0.4
	github.com/lestrrat-go/dsig v1.4.0
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0
	github.com/lestrrat-go/httprc/v3 v3.0.6
	github.com/lestrrat-go/option/v2 v2.0.0
	github.com/segmentio/asm v1.2.1
	github.com/stretchr/testify v1.12.1
	github.com/valyala/fastjson v1.6.10
	golang.org/x/crypto v0.55.0
)

require (
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

retract v3.0.4 // Accidentally introduced data races.
