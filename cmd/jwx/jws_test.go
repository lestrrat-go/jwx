package main

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

func TestResolveSignatureAlgorithm(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		alg, err := resolveSignatureAlgorithm("RS256")
		require.NoError(t, err)
		require.Equal(t, jwa.RS256(), alg)
	})
	t.Run("unknown", func(t *testing.T) {
		_, err := resolveSignatureAlgorithm("bogus")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid algorithm")
	})
	t.Run("none rejected", func(t *testing.T) {
		_, err := resolveSignatureAlgorithm("none")
		require.Error(t, err)
		require.Contains(t, strings.ToLower(err.Error()), `"none"`)
	})
}
