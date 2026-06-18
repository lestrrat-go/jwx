package jws

import (
	"crypto/ed25519"
	"crypto/rand"
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

// TestAlgorithmsMatch pins the alg-match semantics of algorithmsMatch: it
// matches only on exact string equality or the RFC 9864 generic-vs-specific
// EdDSA relation. The generic/specific alias is KEY-AWARE — a generic "EdDSA"
// only aliases the fully-specified variant ("Ed25519"/"Ed448") that the
// verification key actually is, and the curve cannot be derived from the key
// the pairing fails closed. The two fully-specified variants never match each
// other, and two distinct alg identifiers are never treated as equivalent
// merely because they share an underlying dsig mapping.
func TestAlgorithmsMatch(t *testing.T) {
	t.Parallel()

	// "Ed448" is registered by an extension module, not the main module, so
	// construct it by its on-the-wire identifier string. Without the
	// extension imported there is no Ed448 key type and no curve
	// registration, so any generic/specific alias involving "Ed448" is
	// curve-indeterminate and must fail closed here.
	ed448 := jwa.NewSignatureAlgorithm("Ed448")

	ed25519Pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name string
		a    jwa.SignatureAlgorithm
		b    jwa.SignatureAlgorithm
		key  any
		want bool
	}{
		// Exact-equality matches never need the key.
		{name: "exact equal", a: jwa.HS256(), b: jwa.HS256(), want: true},
		{name: "RS256 exact equal", a: jwa.RS256(), b: jwa.RS256(), want: true},
		{name: "EdDSA vs EdDSA", a: jwa.EdDSA(), b: jwa.EdDSA(), want: true},
		{name: "Ed25519 exact equal", a: jwa.EdDSAEd25519(), b: jwa.EdDSAEd25519(), want: true},
		{name: "Ed448 exact equal", a: ed448, b: ed448, want: true},
		// Generic/specific EdDSA alias matches only when the specific variant
		// equals the key's actual curve. An Ed25519 key aliases generic
		// "EdDSA" to "Ed25519".
		{name: "EdDSA vs Ed25519 alias with Ed25519 key", a: jwa.EdDSA(), b: jwa.EdDSAEd25519(), key: ed25519Pub, want: true},
		{name: "Ed25519 vs EdDSA alias (reverse) with Ed25519 key", a: jwa.EdDSAEd25519(), b: jwa.EdDSA(), key: ed25519Pub, want: true},
		// Generic "EdDSA" verifier with an Ed25519 key must NOT alias an
		// "Ed448" header — the key cannot be Ed448. This is the core
		// key-confusion case the fix closes.
		{name: "EdDSA vs Ed448 alias with Ed25519 key rejects", a: jwa.EdDSA(), b: ed448, key: ed25519Pub, want: false},
		{name: "Ed448 vs EdDSA alias (reverse) with Ed25519 key rejects", a: ed448, b: jwa.EdDSA(), key: ed25519Pub, want: false},
		// Generic/specific alias with no key (curve indeterminate) fails closed.
		{name: "EdDSA vs Ed25519 alias without key fails closed", a: jwa.EdDSA(), b: jwa.EdDSAEd25519(), key: nil, want: false},
		{name: "EdDSA vs Ed448 alias without key fails closed", a: jwa.EdDSA(), b: ed448, key: nil, want: false},
		// Ed25519 and Ed448 are different curves / keys / security levels and
		// are NOT interchangeable. Only the generic "EdDSA" aliases either one.
		{name: "Ed25519 vs Ed448 distinct curves", a: jwa.EdDSAEd25519(), b: ed448, key: ed25519Pub, want: false},
		{name: "Ed448 vs Ed25519 distinct curves (reverse)", a: ed448, b: jwa.EdDSAEd25519(), key: ed25519Pub, want: false},
		{name: "RS256 vs HS256 distinct", a: jwa.RS256(), b: jwa.HS256(), want: false},
		{name: "ES256 vs ES384 distinct", a: jwa.ES256(), b: jwa.ES384(), want: false},
		{name: "EdDSA vs HS256 distinct", a: jwa.EdDSA(), b: jwa.HS256(), key: ed25519Pub, want: false},
		// Two distinct alg names that resolve to the same dsig algorithm
		// (HS256) must still be a mismatch — a shared dsig mapping is NOT an
		// alias. This is the algorithm-confusion case the guard exists to stop.
		{name: "custom alg sharing dsig mapping not equivalent", a: jwa.NewSignatureAlgorithm("CUSTOM-HMAC"), b: jwa.HS256(), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, algorithmsMatch(tc.a, tc.b, tc.key))
		})
	}
}
