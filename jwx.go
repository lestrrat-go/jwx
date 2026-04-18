//go:generate ./scripts/jwxcodegen.sh generate-readfile
//go:generate ./scripts/jwxcodegen.sh generate-all-options
//go:generate go tool stringer -type=FormatKind
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
// # Requirements
//
// v4 uses the experimental encoding/json/v2 API, so consumers must build
// with:
//
//   - Go 1.26.0 or later (see go.mod for the exact minimum)
//   - GOEXPERIMENT=jsonv2 set in the environment for every `go build`,
//     `go test`, `go run`, and `go generate` invocation
//
// Without GOEXPERIMENT=jsonv2 the Go toolchain reports
// `build constraints exclude all Go files` and the module will not build.
//
// Examples are stored in a separate Go module (to avoid adding
// dependencies to this module), and thus does not appear in the
// online documentation for this module.
// You can find the examples in Github at https://github.com/jwx-go/examples/tree/v4
//
// You can find more high level documentation at Github (https://github.com/lestrrat-go/jwx/tree/develop/v4/docs)
//
// FAQ style documentation can be found in the repository (https://github.com/lestrrat-go/jwx/tree/develop/v4/docs/99-faq.md)
package jwx

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/option/v3"
)

// implementationNoteStreaming documents a library-wide design decision:
// jwx remains buffer-oriented for parse/sign/verify/encrypt/decrypt paths
// even when an io.Reader helper exists as an input convenience.
//
// We investigated true streaming support across the core packages and
// companion modules, including PQC algorithms. Some signature families can
// share an incremental core because the underlying crypto signs or verifies a
// digest or other compact representative rather than the full message:
// HMAC, RSA, ECDSA, ES256K, and the composite-signature companion all fit
// that model. ML-DSA is also more nuanced than its top-level message-based
// API suggests because the underlying library supports external-mu signing.
//
// That is still not enough for a coherent library-wide streaming design.
// Other supported signature algorithms such as Ed25519 and Ed448 are exposed
// as whole-message operations at the crypto-library surface, and JWE content
// encryption is the decisive blocker: the supported content-encryption stack,
// especially AES-GCM via cipher.AEAD, is fundamentally exposed through
// one-shot buffer APIs. As long as any required primitive in the supported
// stack remains non-streaming, true streaming support would force split code
// paths and algorithm-specific execution models.
//
// jwx intentionally avoids that divergence. Until the full supported
// primitive set supports a coherent streaming model end to end, the public
// JOSE operations stay byte-slice/buffer oriented.
type implementationNoteStreaming struct{}

var _ implementationNoteStreaming

// Settings configures global settings for the jwx package.
//
// All options accepted here have process-global effect and are intended
// to be applied exactly once at program startup, before any goroutine
// begins parsing JWx payloads. See the godoc on individual GlobalOption
// constructors (e.g. [WithUseNumber]) for the concurrency contract of
// each setting.
//
// Returns a non-nil error and applies no changes if any option fails
// validation (for example, a nil [WithBase64Encoder] or [WithBase64Decoder]).
func Settings(options ...GlobalOption) error {
	// Validate first so the call is all-or-nothing on error.
	// For interface-typed options, a nil value is unwrapped when passed
	// through any, so option.Get returns ok=false — treat that as "nil".
	for _, opt := range options {
		switch opt.Ident() {
		case identBase64Encoder{}:
			if v, ok := option.Get[Base64Encoder](opt); !ok || v == nil {
				return fmt.Errorf(`jwx.Settings: WithBase64Encoder must not be nil`)
			}
		case identBase64Decoder{}:
			if v, ok := option.Get[Base64Decoder](opt); !ok || v == nil {
				return fmt.Errorf(`jwx.Settings: WithBase64Decoder must not be nil`)
			}
		}
	}

	for _, opt := range options {
		switch opt.Ident() {
		case identUseNumber{}:
			json.SetUseNumber(option.MustGet[bool](opt))
		case identBase64Encoder{}:
			base64.SetEncoder(option.MustGet[Base64Encoder](opt))
		case identBase64Decoder{}:
			base64.SetDecoder(option.MustGet[Base64Decoder](opt))
		}
	}
	return nil
}
