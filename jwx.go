//go:generate ./scripts/jwxcodegen.sh generate-readfile
//go:generate ./scripts/jwxcodegen.sh generate-all-options
//go:generate stringer -type=FormatKind
//go:generate mv formatkind_string.go formatkind_string_gen.go

// Package jwx contains tools that deal with the various JWx (JOSE)
// technologies such as JWT, JWS, JWE, etc in Go.
//
//	JWS (https://tools.ietf.org/html/rfc7515)
//	JWE (https://tools.ietf.org/html/rfc7516)
//	JWK (https://tools.ietf.org/html/rfc7517)
//	JWA (https://tools.ietf.org/html/rfc7518)
//	JWT (https://tools.ietf.org/html/rfc7519)
//
// Examples are stored in a separate Go module (to avoid adding
// dependencies to this module), and thus does not appear in the
// online documentation for this module.
// You can find the examples in Github at https://github.com/lestrrat-go/jwx/tree/v3/examples
//
// You can find more high level documentation at Github (https://github.com/lestrrat-go/jwx/tree/v2)
//
// FAQ style documentation can be found in the repository (https://github.com/lestrrat-go/jwx/tree/develop/v3/docs)
package jwx

import (
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/option/v3"
)

// Settings configures global settings for the jwx package.
func Settings(options ...GlobalOption) {
	for _, opt := range options {
		//nolint:forcetypeassert
		switch opt.Ident() {
		case identUseNumber{}:
			json.SetUseNumber(option.MustGet[bool](opt))
		}
	}
}
