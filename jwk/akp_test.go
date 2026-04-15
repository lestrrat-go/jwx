package jwk

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

// TestAKPThumbprintIncludesAlg locks in the RFC 7638 / RFC 9802 contract that
// AKP thumbprints hash the canonical JSON of {alg, kty, pub} in lexicographic
// order. A real PQ algorithm string (e.g. ML-DSA-44) lives in the ML-DSA
// extension module, so this test uses jwa.RS256() as a stand-in registered
// algorithm — the byte value of alg is irrelevant; what matters is that it
// appears in the hash input.
func TestAKPThumbprintIncludesAlg(t *testing.T) {
	pub := []byte("pub-bytes-for-thumbprint")
	b64Pub := base64.EncodeToString(pub)
	alg := jwa.RS256()

	expected := sha256.Sum256(fmt.Appendf(nil, `{"alg":%q,"kty":"AKP","pub":%q}`, alg.String(), b64Pub))

	t.Run("public key", func(t *testing.T) {
		k := newAKPPublicKey()
		require.NoError(t, k.Set(AKPPubKey, pub))
		require.NoError(t, k.Set(AlgorithmKey, alg))

		got, err := k.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		require.Equal(t, expected[:], got)
	})

	t.Run("private key", func(t *testing.T) {
		k := newAKPPrivateKey()
		require.NoError(t, k.Set(AKPPubKey, pub))
		require.NoError(t, k.Set(AKPPrivKey, []byte("priv-bytes")))
		require.NoError(t, k.Set(AlgorithmKey, alg))

		got, err := k.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		require.Equal(t, expected[:], got)
	})
}

func TestAKPThumbprintRequiresAlg(t *testing.T) {
	pub := []byte("pub-bytes")

	t.Run("public key without alg", func(t *testing.T) {
		k := newAKPPublicKey()
		require.NoError(t, k.Set(AKPPubKey, pub))
		_, err := k.Thumbprint(crypto.SHA256)
		require.Error(t, err)
	})

	t.Run("private key without alg", func(t *testing.T) {
		k := newAKPPrivateKey()
		require.NoError(t, k.Set(AKPPubKey, pub))
		require.NoError(t, k.Set(AKPPrivKey, []byte("priv-bytes")))
		_, err := k.Thumbprint(crypto.SHA256)
		require.Error(t, err)
	})
}
