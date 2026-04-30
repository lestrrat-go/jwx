package jwebb_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/stretchr/testify/require"
)

// TestRegisterMLKEMAlgorithmAcceptsNewIdentifier locks that the
// public Register* surface adds the algorithm to the dispatch
// registry and IsMLKEM reports it. Override semantics (built-in
// identifiers can be re-registered) are documented as a privileged
// extension point — see RegisterHPKEAlgorithm's godoc for the full
// design rationale.
func TestRegisterMLKEMAlgorithmAcceptsNewIdentifier(t *testing.T) {
	const custom = "ML-KEM-768-CUSTOM"
	err := jwebb.RegisterMLKEMAlgorithm(custom)
	require.NoError(t, err)
	t.Cleanup(func() { jwebb.UnregisterMLKEMAlgorithm(custom) })
	require.True(t, jwebb.IsMLKEM(custom))
}

func TestRegisterMLKEMDirectAlgorithmAcceptsNewIdentifier(t *testing.T) {
	const custom = "ML-KEM-1024-DIRECT-CUSTOM"
	err := jwebb.RegisterMLKEMDirectAlgorithm(custom)
	require.NoError(t, err)
	t.Cleanup(func() { jwebb.UnregisterMLKEMDirectAlgorithm(custom) })
	require.True(t, jwebb.IsMLKEMDirect(custom))
}
