package jwk_test

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func TestOKPRejectsInvalidBuiltinLengths(t *testing.T) {
	makeEncoded := func(size int) string {
		return base64.EncodeToString(make([]byte, size))
	}

	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "ParseKey/Ed25519 public",
			src:  fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`, makeEncoded(ed25519.PublicKeySize-1)),
			want: "wrong public key size",
		},
		{
			name: "ParseKey/Ed25519 private",
			src:  fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s","d":"%s"}`, makeEncoded(ed25519.PublicKeySize), makeEncoded(ed25519.SeedSize-1)),
			want: "wrong private key size",
		},
		{
			name: "ParseKey/X25519 public",
			src:  fmt.Sprintf(`{"kty":"OKP","crv":"X25519","x":"%s"}`, makeEncoded(31)),
			want: "wrong public key size",
		},
		{
			name: "ParseKey/X25519 private",
			src:  fmt.Sprintf(`{"kty":"OKP","crv":"X25519","x":"%s","d":"%s"}`, makeEncoded(32), makeEncoded(31)),
			want: "wrong private key size",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwk.ParseKey([]byte(tc.src))
			require.Error(t, err)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestOKPImportRejectsInvalidEd25519Lengths(t *testing.T) {
	t.Run("PublicKey", func(t *testing.T) {
		_, err := jwk.Import[jwk.OKPPublicKey](ed25519.PublicKey(make([]byte, ed25519.PublicKeySize-1)))
		require.Error(t, err)
		require.ErrorContains(t, err, "wrong public key size")
		require.ErrorIs(t, err, jwk.ImportError())
		require.True(t, errors.Is(err, jwk.ImportError()))
	})

	t.Run("PrivateKey", func(t *testing.T) {
		_, err := jwk.Import[jwk.OKPPrivateKey](ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize-1)))
		require.Error(t, err)
		require.ErrorContains(t, err, "wrong private key size")
		require.ErrorIs(t, err, jwk.ImportError())
		require.True(t, errors.Is(err, jwk.ImportError()))
	})
}
