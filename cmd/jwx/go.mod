module github.com/lestrrat-go/jwx/v4/cmd/jwx

go 1.26.0

require (
	github.com/lestrrat-go/jwx/v4 v4.0.0
	github.com/stretchr/testify v1.11.1
	github.com/urfave/cli/v2 v2.26.0
	golang.org/x/crypto v0.54.0
	golang.org/x/term v0.45.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/lestrrat-go/dsig v1.3.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	github.com/xrash/smetrics v0.0.0-20231213231151-1d8dd44e695e // indirect
	golang.org/x/sys v0.47.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/lestrrat-go/jwx/v4 v4.0.0 => ../..
