package base64

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	testcases := []struct {
		Name     string
		Encoding *base64.Encoding
	}{
		{
			Name:     "base64.RawURLEncoding",
			Encoding: base64.RawURLEncoding,
		},
		{
			Name:     "base64.URLEncoding",
			Encoding: base64.URLEncoding,
		},
		{
			Name:     "base64.RawStdEncoding",
			Encoding: base64.RawStdEncoding,
		},
		{
			Name:     "base64.StdEncoding",
			Encoding: base64.StdEncoding,
		},
	}

	var payload = []byte("Hello, World")
	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			dst := make([]byte, tc.Encoding.EncodedLen(len(payload)))
			tc.Encoding.Encode(dst, payload)

			decoded, err := Decode(dst)
			require.NoError(t, err, `Decode should succeed`)
			require.Equal(t, payload, decoded, `decoded content should match`)
		})
	}
}
