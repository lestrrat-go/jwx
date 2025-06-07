package base64_test

import (
	stdbase64 "encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	testcases := []struct {
		Name     string
		Encoding *stdbase64.Encoding
	}{
		{
			Name:     "base64.RawURLEncoding",
			Encoding: stdbase64.RawURLEncoding,
		},
		{
			Name:     "base64.URLEncoding",
			Encoding: stdbase64.URLEncoding,
		},
		{
			Name:     "base64.RawStdEncoding",
			Encoding: stdbase64.RawStdEncoding,
		},
		{
			Name:     "base64.StdEncoding",
			Encoding: stdbase64.StdEncoding,
		},
	}

	var payload = []byte("Hello, World")
	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			dst := make([]byte, tc.Encoding.EncodedLen(len(payload)))
			tc.Encoding.Encode(dst, payload)

			decoded, err := base64.Decode(dst)
			require.NoError(t, err, `Decode should succeed`)
			require.Equal(t, payload, decoded, `decoded content should match`)
		})
	}
}

func TestAppendEncode(t *testing.T) {
	dst := []byte("Hello, ")
	result := base64.AppendEncode(dst, []byte("World!"))
	require.Equal(t, "Hello, V29ybGQh", string(result), `result should match expected value`)
}
