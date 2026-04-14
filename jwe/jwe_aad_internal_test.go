package jwe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestConcatAADDoesNotAlias is a regression test for an AAD aliasing
// bug where the decrypt path used
// `append(append(computedAad, '.'), aad...)` and computedAad aliased
// msg.rawProtectedHeaders, silently mutating its backing storage when
// spare capacity was available.
func TestConcatAADDoesNotAlias(t *testing.T) {
	t.Run("no external aad returns input as-is", func(t *testing.T) {
		computed := []byte("protected")
		require.Equal(t, computed, concatAAD(computed, nil))
		require.Equal(t, computed, concatAAD(computed, []byte{}))
	})

	t.Run("computed's backing array past len is untouched", func(t *testing.T) {
		const head = "AAAAAAAAAA"       // 10 bytes
		const sentinel = byte('Z')
		backing := make([]byte, 64)
		copy(backing, head)
		for i := len(head); i < len(backing); i++ {
			backing[i] = sentinel
		}
		computed := backing[:len(head)]
		require.Equal(t, 64, cap(computed))

		out := concatAAD(computed, []byte("external"))
		require.Equal(t, []byte("AAAAAAAAAA.external"), out)

		// computed's visible content unchanged.
		require.Equal(t, []byte(head), computed)
		// Bytes past len in the shared backing array unchanged — this
		// is the actual aliasing regression we're guarding against.
		tail := computed[:cap(computed)][len(head):]
		for i, b := range tail {
			require.Equal(t, sentinel, b, `backing[%d] past computed's length must be unchanged`, len(head)+i)
		}
	})

	t.Run("aad's backing array past len is untouched", func(t *testing.T) {
		const body = "AAD!?" // 5 bytes
		const sentinel = byte('Y')
		backing := make([]byte, 32)
		copy(backing, body)
		for i := len(body); i < len(backing); i++ {
			backing[i] = sentinel
		}
		aad := backing[:len(body)]
		require.Equal(t, 32, cap(aad))

		out := concatAAD([]byte("protected"), aad)
		require.Equal(t, []byte("protected.AAD!?"), out)

		require.Equal(t, []byte(body), aad)
		tail := aad[:cap(aad)][len(body):]
		for i, b := range tail {
			require.Equal(t, sentinel, b, `aad backing[%d] past len must be unchanged`, len(body)+i)
		}
	})
}
