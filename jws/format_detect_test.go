package jws

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

func TestDetectParseFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  []byte
		want int
	}{
		{
			name: "space then BOM then JSON stays compact",
			src:  []byte(" \uFEFF{\"payload\":\"x\"}"),
			want: fmtCompact,
		},
		{
			name: "leading unicode whitespace then JSON",
			src:  []byte("\u3000{\"payload\":\"x\"}"),
			want: fmtJSON,
		},
		{
			name: "leading unicode whitespace then compact",
			src:  []byte("\u3000eyJhbGciOiJIUzI1NiJ9"),
			want: fmtCompact,
		},
		{
			name: "empty input",
			want: 0,
		},
		{
			name: "all whitespace input",
			src:  []byte("\t\r\n "),
			want: 0,
		},
		{
			name: "unicode whitespace only",
			src:  []byte("\u3000"),
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, detectParseFormat(tc.src))
		})
	}
}

// TestAlgorithmMatch pins the exact-string alg-match semantics: the protected
// header "alg" matches the verification algorithm if and only if their on-the-
// wire identifiers are equal. There is no aliasing — in particular the
// deprecated polymorphic "EdDSA" and the fully-specified "Ed25519"/"Ed448"
// identifiers are distinct per RFC 9864, and the two fully-specified variants
// are distinct from each other. Two distinct alg names that happen to share an
// underlying dsig mapping are likewise NOT equivalent.
func TestAlgorithmMatch(t *testing.T) {
	t.Parallel()

	// "Ed448" is registered by an extension module, not the main module, so
	// construct it by its on-the-wire identifier string.
	ed448 := jwa.NewSignatureAlgorithm("Ed448")

	tests := []struct {
		name string
		a    jwa.SignatureAlgorithm
		b    jwa.SignatureAlgorithm
		want bool
	}{
		// Equal identifiers match.
		{name: "exact equal", a: jwa.HS256(), b: jwa.HS256(), want: true},
		{name: "RS256 exact equal", a: jwa.RS256(), b: jwa.RS256(), want: true},
		{name: "EdDSA vs EdDSA", a: jwa.EdDSA(), b: jwa.EdDSA(), want: true},
		{name: "Ed25519 exact equal", a: jwa.EdDSAEd25519(), b: jwa.EdDSAEd25519(), want: true},
		{name: "Ed448 exact equal", a: ed448, b: ed448, want: true},
		// RFC 9864: the generic "EdDSA" and the fully-specified variants are
		// distinct identifiers and do NOT alias one another.
		{name: "EdDSA vs Ed25519 distinct", a: jwa.EdDSA(), b: jwa.EdDSAEd25519(), want: false},
		{name: "Ed25519 vs EdDSA distinct (reverse)", a: jwa.EdDSAEd25519(), b: jwa.EdDSA(), want: false},
		{name: "EdDSA vs Ed448 distinct", a: jwa.EdDSA(), b: ed448, want: false},
		{name: "Ed448 vs EdDSA distinct (reverse)", a: ed448, b: jwa.EdDSA(), want: false},
		// The two fully-specified EdDSA variants are different curves / keys /
		// security levels and never match each other.
		{name: "Ed25519 vs Ed448 distinct curves", a: jwa.EdDSAEd25519(), b: ed448, want: false},
		{name: "Ed448 vs Ed25519 distinct curves (reverse)", a: ed448, b: jwa.EdDSAEd25519(), want: false},
		{name: "RS256 vs HS256 distinct", a: jwa.RS256(), b: jwa.HS256(), want: false},
		{name: "ES256 vs ES384 distinct", a: jwa.ES256(), b: jwa.ES384(), want: false},
		{name: "EdDSA vs HS256 distinct", a: jwa.EdDSA(), b: jwa.HS256(), want: false},
		// Two distinct alg names that resolve to the same dsig algorithm
		// (HS256) must still be a mismatch — a shared dsig mapping is NOT an
		// alias. This is the algorithm-confusion case the guard exists to stop.
		{name: "custom alg sharing dsig mapping not equivalent", a: jwa.NewSignatureAlgorithm("CUSTOM-HMAC"), b: jwa.HS256(), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, tc.a.String() == tc.b.String())
		})
	}
}
