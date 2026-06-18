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

// TestAlgorithmsMatch pins the closed-set semantics of algorithmsMatch: it
// matches only on exact string equality or membership in the same explicit
// RFC 9864 alias group. It must NOT treat two distinct alg identifiers as
// equivalent merely because they share an underlying dsig mapping.
func TestAlgorithmsMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    jwa.SignatureAlgorithm
		b    jwa.SignatureAlgorithm
		want bool
	}{
		{name: "exact equal", a: jwa.HS256(), b: jwa.HS256(), want: true},
		{name: "EdDSA vs Ed25519 alias", a: jwa.EdDSA(), b: jwa.EdDSAEd25519(), want: true},
		{name: "Ed25519 vs EdDSA alias (reverse)", a: jwa.EdDSAEd25519(), b: jwa.EdDSA(), want: true},
		{name: "RS256 vs HS256 distinct", a: jwa.RS256(), b: jwa.HS256(), want: false},
		{name: "ES256 vs ES384 distinct", a: jwa.ES256(), b: jwa.ES384(), want: false},
		{name: "EdDSA vs HS256 distinct", a: jwa.EdDSA(), b: jwa.HS256(), want: false},
		// Two distinct alg names that resolve to the same dsig algorithm
		// (HS256) must still be a mismatch — a shared dsig mapping is NOT an
		// alias. This is the algorithm-confusion case the closed set guards.
		{name: "custom alg sharing dsig mapping not equivalent", a: jwa.NewSignatureAlgorithm("CUSTOM-HMAC"), b: jwa.HS256(), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, algorithmsMatch(tc.a, tc.b))
		})
	}
}
