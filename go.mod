module github.com/lestrrat-go/jwx/v3

go 1.26.0

require (
	github.com/lestrrat-go/dsig v1.1.0
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1
	github.com/stretchr/testify v1.11.1
	github.com/valyala/fastjson v1.6.10
	golang.org/x/crypto v0.49.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract v3.0.4 // Accidentally introduced data races.
