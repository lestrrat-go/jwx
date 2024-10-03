//go:build jwx_es256k
// +build jwx_es256k

package jwa_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

func TestSecp256k1(t *testing.T) {
	t.Parallel()
	t.Run(`accept jwa constant Secp256k1`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.EllipticCurveAlgorithm
		require.NoError(t, dst.Accept(jwa.Secp256k1), `accept is successful`)
		require.Equal(t, jwa.Secp256k1, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string secp256k1`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.EllipticCurveAlgorithm
		require.NoError(t, dst.Accept("secp256k1"), `accept is successful`)
		require.Equal(t, jwa.Secp256k1, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for secp256k1`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.EllipticCurveAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "secp256k1"}), `accept is successful`)
		require.Equal(t, jwa.Secp256k1, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for secp256k1`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "secp256k1", jwa.Secp256k1.String(), `stringified value matches`)
	})
}
