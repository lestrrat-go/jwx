package jwkunsafe_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk/jwkunsafe"
	"github.com/stretchr/testify/require"
)

func TestNewKey(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		Name string
		Kty  jwa.KeyType
	}{
		{"EC", jwa.EC()},
		{"OKP", jwa.OKP()},
		{"RSA", jwa.RSA()},
		{"OctetSeq", jwa.OctetSeq()},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			key, err := jwkunsafe.NewKey(tc.Kty)
			require.NoError(t, err, "NewKey(%s) should succeed", tc.Kty)
			require.NotNil(t, key)
			require.Equal(t, tc.Kty, key.KeyType(), "KeyType should match")
		})
	}

	t.Run("UnknownKeyType", func(t *testing.T) {
		t.Parallel()
		_, err := jwkunsafe.NewKey(jwa.InvalidKeyType())
		require.Error(t, err, "NewKey with unknown key type should fail")
	})
}

func TestNewPublicKey(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		Name string
		Kty  jwa.KeyType
	}{
		{"EC", jwa.EC()},
		{"OKP", jwa.OKP()},
		{"RSA", jwa.RSA()},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			key, err := jwkunsafe.NewPublicKey(tc.Kty)
			require.NoError(t, err, "NewPublicKey(%s) should succeed", tc.Kty)
			require.NotNil(t, key)
			require.Equal(t, tc.Kty, key.KeyType(), "KeyType should match")
		})
	}

	t.Run("OctetSeqHasNoPublicKey", func(t *testing.T) {
		t.Parallel()
		_, err := jwkunsafe.NewPublicKey(jwa.OctetSeq())
		require.Error(t, err, "NewPublicKey(OctetSeq) should fail — symmetric keys have no public variant")
	})

	t.Run("UnknownKeyType", func(t *testing.T) {
		t.Parallel()
		_, err := jwkunsafe.NewPublicKey(jwa.InvalidKeyType())
		require.Error(t, err, "NewPublicKey with unknown key type should fail")
	})
}
