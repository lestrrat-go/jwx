package jwk_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/jwk"
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
		_, err := jwk.Import(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize-1)))
		require.Error(t, err)
		require.ErrorContains(t, err, "wrong public key size")
	})

	t.Run("PrivateKey", func(t *testing.T) {
		_, err := jwk.Import(ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize-1)))
		require.Error(t, err)
		require.ErrorContains(t, err, "wrong private key size")
	})
}

// smallOrderEd25519Keys holds the little-endian encodings of the Ed25519
// points of order 1, 2, 4, and 8, including the non-canonical encodings
// that reduce to the same point.
var smallOrderEd25519Keys = map[string]string{
	"zero":                       "0000000000000000000000000000000000000000000000000000000000000000",
	"identity":                   "0100000000000000000000000000000000000000000000000000000000000000",
	"order 2":                    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"order 4 canonical":          "0000000000000000000000000000000000000000000000000000000000000080",
	"order 8 a":                  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"order 8 b":                  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"order 8 a with sign bit":    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"order 8 b with sign bit":    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"non-canonical zero":         "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"non-canonical identity":     "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"non-canonical order 2 sign": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func TestOKPAcceptsSmallOrderEd25519PublicKeysByDefault(t *testing.T) {
	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 1

	src := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`, base64.EncodeToString(identity))
	key, err := jwk.ParseKey([]byte(src))
	require.NoError(t, err)
	require.NoError(t, key.Validate())

	_, err = jwk.Import(ed25519.PublicKey(identity))
	require.NoError(t, err)
}

func TestOKPRejectsSmallOrderEd25519PublicKeys(t *testing.T) {
	jwk.Configure(jwk.WithRejectSmallOrderEd25519Keys(true))
	t.Cleanup(func() {
		jwk.Configure(jwk.WithRejectSmallOrderEd25519Keys(false))
	})

	for name, hexKey := range smallOrderEd25519Keys {
		raw, err := hex.DecodeString(hexKey)
		require.NoError(t, err)
		require.Len(t, raw, ed25519.PublicKeySize)

		t.Run("ParseKey/"+name, func(t *testing.T) {
			src := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`, base64.EncodeToString(raw))
			_, err := jwk.ParseKey([]byte(src))
			require.Error(t, err)
			require.ErrorContains(t, err, "small-order")
		})

		t.Run("Import/"+name, func(t *testing.T) {
			_, err := jwk.Import(ed25519.PublicKey(raw))
			require.Error(t, err)
			require.ErrorContains(t, err, "small-order")
		})

		t.Run("Validate/"+name, func(t *testing.T) {
			// Build a valid key, then overwrite "x" so that only Validate can catch it.
			pub, _, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			key, err := jwk.Import(pub)
			require.NoError(t, err)
			require.NoError(t, key.Set(jwk.OKPXKey, raw))
			require.Error(t, key.Validate())
			require.ErrorContains(t, key.Validate(), "small-order")
		})
	}

	t.Run("accepts a generated key", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		key, err := jwk.Import(pub)
		require.NoError(t, err)
		require.NoError(t, key.Validate())
	})
}
