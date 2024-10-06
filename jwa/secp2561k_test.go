//go:build jwx_es256k
// +build jwx_es256k

package jwa_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

func TestSecp256k1(t *testing.T) {
	t.Parallel()
	t.Run(`accept jwa constant Secp256k1`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.EllipticCurveAlgorithm
		require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf("%q", jwa.Secp256k1().String())), &dst), `Unmarshal is successful`)
		require.Equal(t, jwa.Secp256k1(), dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for secp256k1`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "secp256k1", jwa.Secp256k1().String(), `stringified value matches`)
	})
}
