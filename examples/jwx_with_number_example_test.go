//go:build ignore
// +build ignore

package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"log"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func ExampleJWX_DecoderSettings() {
	// This has not been enabled in this example, but if you want to
	// parse numbers in the incoming JSON objects as json.Number
	// instead of floats, you can use the following call to globally
	// affect the behavior of JSON parsing.

	// func init() {
	//   jwx.DecoderSettings(jwx.WithUseNumber(true))
	// }
}
