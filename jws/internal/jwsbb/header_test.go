package jwsbb_test

import (
	"testing"

	jwsbb "github.com/lestrrat-go/jwx/v4/jws/internal/jwsbb"
	"github.com/stretchr/testify/require"
)

func TestHeaderForEachKey(t *testing.T) {
	t.Run("enumerates parameter names in order including duplicates", func(t *testing.T) {
		h := jwsbb.HeaderParse([]byte(`{"alg":"HS256","typ":"JWT","alg":"none"}`))
		var got []string
		require.NoError(t, jwsbb.HeaderForEachKey(h, func(name []byte) {
			got = append(got, string(name))
		}))
		// fastjson keeps duplicate object members, so both "alg" entries are
		// reported in document order — this is what lets a caller detect a
		// duplicate parameter name.
		require.Equal(t, []string{"alg", "typ", "alg"}, got)
	})

	t.Run("returns error for malformed JSON", func(t *testing.T) {
		h := jwsbb.HeaderParse([]byte(`{not valid`))
		require.Error(t, jwsbb.HeaderForEachKey(h, func([]byte) {}))
	})

	t.Run("returns error when the header is not a JSON object", func(t *testing.T) {
		h := jwsbb.HeaderParse([]byte(`"just a string"`))
		require.Error(t, jwsbb.HeaderForEachKey(h, func([]byte) {}))
	})
}
