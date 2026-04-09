package jwebb_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/stretchr/testify/require"
)

// mockHPKEPublicKey implements jwebb.HPKEKeyEncrypter for testing.
type mockHPKEPublicKey struct {
	sealedCEK []byte
	enc       []byte
	err       error
}

func (m *mockHPKEPublicKey) EncryptHPKE(_ []byte, alg, calg string) ([]byte, []byte, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.sealedCEK, m.enc, nil
}

// mockHPKEPrivateKey implements jwebb.HPKEKeyDecrypter for testing.
type mockHPKEPrivateKey struct {
	cek []byte
	err error
}

func (m *mockHPKEPrivateKey) DecryptHPKE(_ []byte, alg, calg string, enc []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.cek, nil
}

func TestKeyEncryptHPKECustom(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cek := []byte("0123456789abcdef")
		wantSealed := []byte("sealed-cek")
		wantEnc := []byte("encapsulated-key")

		pub := &mockHPKEPublicKey{sealedCEK: wantSealed, enc: wantEnc}

		src, err := jwebb.KeyEncryptHPKECustom(cek, "HPKE-0-KE", "A128GCM", pub)
		require.NoError(t, err)
		require.Equal(t, wantSealed, src.Bytes())

		bek, ok := src.(keygen.ByteWithEncapsulatedKey)
		require.True(t, ok)
		require.Equal(t, wantEnc, bek.Ciphertext)
	})

	t.Run("error", func(t *testing.T) {
		pub := &mockHPKEPublicKey{err: fmt.Errorf("mock encrypt failure")}

		_, err := jwebb.KeyEncryptHPKECustom(nil, "HPKE-0-KE", "A128GCM", pub)
		require.Error(t, err)
		require.ErrorContains(t, err, "mock encrypt failure")
	})
}

func TestKeyDecryptHPKECustom(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		wantCEK := []byte("0123456789abcdef")
		priv := &mockHPKEPrivateKey{cek: wantCEK}

		got, err := jwebb.KeyDecryptHPKECustom([]byte("sealed"), "HPKE-0-KE", "A128GCM", priv, []byte("enc"))
		require.NoError(t, err)
		require.Equal(t, wantCEK, got)
	})

	t.Run("error", func(t *testing.T) {
		priv := &mockHPKEPrivateKey{err: fmt.Errorf("mock decrypt failure")}

		_, err := jwebb.KeyDecryptHPKECustom(nil, "HPKE-0-KE", "A128GCM", priv, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "mock decrypt failure")
	})
}

func TestKeyEncryptHPKEKEDispatch(t *testing.T) {
	t.Run("custom key takes precedence", func(t *testing.T) {
		cek := []byte("0123456789abcdef")
		wantSealed := []byte("custom-sealed")
		wantEnc := []byte("custom-enc")

		pub := &mockHPKEPublicKey{sealedCEK: wantSealed, enc: wantEnc}

		src, err := jwebb.KeyEncryptHPKEKE(cek, "HPKE-0-KE", "A128GCM", pub)
		require.NoError(t, err)
		require.Equal(t, wantSealed, src.Bytes())

		bek, ok := src.(keygen.ByteWithEncapsulatedKey)
		require.True(t, ok)
		require.Equal(t, wantEnc, bek.Ciphertext)
	})
}

func TestKeyDecryptHPKEKEDispatch(t *testing.T) {
	t.Run("custom key takes precedence", func(t *testing.T) {
		wantCEK := []byte("0123456789abcdef")
		priv := &mockHPKEPrivateKey{cek: wantCEK}

		got, err := jwebb.KeyDecryptHPKEKE([]byte("sealed"), "HPKE-0-KE", "A128GCM", priv, []byte("enc"))
		require.NoError(t, err)
		require.Equal(t, wantCEK, got)
	})
}

func TestRegisterHPKEAlgorithm(t *testing.T) {
	t.Run("built-in algorithms are registered", func(t *testing.T) {
		for _, alg := range []string{
			"HPKE-0-KE", "HPKE-1-KE", "HPKE-2-KE",
			"HPKE-3-KE", "HPKE-4-KE", "HPKE-7-KE",
		} {
			require.True(t, jwebb.IsHPKE(alg), "expected IsHPKE(%q) to be true", alg)
		}
	})

	t.Run("unregistered algorithm returns false", func(t *testing.T) {
		require.False(t, jwebb.IsHPKE("HPKE-99-KE"))
	})

	t.Run("dynamic registration", func(t *testing.T) {
		const custom = "HPKE-99-KE"
		require.False(t, jwebb.IsHPKE(custom))

		jwebb.RegisterHPKEAlgorithm(custom)
		t.Cleanup(func() { jwebb.UnregisterHPKEAlgorithm(custom) })
		require.True(t, jwebb.IsHPKE(custom))
	})
}
