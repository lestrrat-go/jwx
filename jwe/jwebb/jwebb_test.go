package jwebb_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/stretchr/testify/require"
)

// Common test data
var (
	// Test CEK (Content Encryption Key)
	testCEK = []byte("0123456789abcdef")

	// Test shared keys of various sizes
	testSharedKey16  = []byte("0123456789abcdef")                 // 16 bytes for A128KW/A128GCMKW
	testSharedKey32  = []byte("0123456789abcdef0123456789abcdef") // 32 bytes for A256KW
	testSharedKeyStr = []byte("shared-key-bytes")                 // Generic shared key

	// Test password
	testPassword = []byte("password123")

	// ECDH-ES party info
	testAPU = []byte("Alice")
	testAPV = []byte("Bob")

	// Common test cases for algorithm validation
	invalidAlgTestCase = struct {
		name string
		alg  string
		want bool
	}{"invalid", "invalid-alg", false}

	emptyAlgTestCase = struct {
		name string
		alg  string
		want bool
	}{"empty", "", false}

	aeskwFalseTestCase = struct {
		name string
		alg  string
		want bool
	}{"A128KW", tokens.A128KW, false}
)

func TestKeyEncryptionIsAESKW(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		want bool
	}{
		{"A128KW", tokens.A128KW, true},
		{"A192KW", tokens.A192KW, true},
		{"A256KW", tokens.A256KW, true},
		invalidAlgTestCase,
		emptyAlgTestCase,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, jwebb.IsAESKW(tt.alg))
		})
	}
}

func TestKeyEncryptionIsDirect(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		want bool
	}{
		{"dir", tokens.DIRECT, true},
		invalidAlgTestCase,
		aeskwFalseTestCase,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, jwebb.IsDirect(tt.alg))
		})
	}
}

func TestKeyEncryptionIsPBES2(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		want bool
	}{
		{"PBES2_HS256_A128KW", tokens.PBES2_HS256_A128KW, true},
		{"PBES2_HS384_A192KW", tokens.PBES2_HS384_A192KW, true},
		{"PBES2_HS512_A256KW", tokens.PBES2_HS512_A256KW, true},
		invalidAlgTestCase,
		aeskwFalseTestCase,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, jwebb.IsPBES2(tt.alg))
		})
	}
}

func TestKeyEncryptionIsAESGCMKW(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		want bool
	}{
		{"A128GCMKW", tokens.A128GCMKW, true},
		{"A192GCMKW", tokens.A192GCMKW, true},
		{"A256GCMKW", tokens.A256GCMKW, true},
		invalidAlgTestCase,
		aeskwFalseTestCase,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, jwebb.IsAESGCMKW(tt.alg))
		})
	}
}

func TestKeyEncryptionIsECDHES(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		want bool
	}{
		{"ECDH_ES", tokens.ECDH_ES, true},
		{"ECDH_ES_A128KW", tokens.ECDH_ES_A128KW, true},
		{"ECDH_ES_A192KW", tokens.ECDH_ES_A192KW, true},
		{"ECDH_ES_A256KW", tokens.ECDH_ES_A256KW, true},
		invalidAlgTestCase,
		aeskwFalseTestCase,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, jwebb.IsECDHES(tt.alg))
		})
	}
}

func TestKeyEncryptionIsRSA15(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		want bool
	}{
		{"RSA1_5", tokens.RSA1_5, true},
		invalidAlgTestCase,
		{"RSA_OAEP", tokens.RSA_OAEP, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, jwebb.IsRSA15(tt.alg))
		})
	}
}

func TestKeyEncryptionIsRSAOAEP(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		want bool
	}{
		{"RSA_OAEP", tokens.RSA_OAEP, true},
		{"RSA_OAEP_256", tokens.RSA_OAEP_256, true},
		{"RSA_OAEP_384", tokens.RSA_OAEP_384, true},
		{"RSA_OAEP_512", tokens.RSA_OAEP_512, true},
		invalidAlgTestCase,
		{"RSA1_5", tokens.RSA1_5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, jwebb.IsRSAOAEP(tt.alg))
		})
	}
}

func TestKeyEncryptAESKW(t *testing.T) {
	cek := testCEK
	sharedkey := testSharedKey32 // 32 bytes for A256KW

	result, err := jwebb.KeyEncryptAESKW(cek, tokens.A256KW, sharedkey)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEqual(t, cek, result.Bytes())
}

func TestKeyEncryptDirect(t *testing.T) {
	cek := testCEK
	sharedkey := testSharedKeyStr

	result, err := jwebb.KeyEncryptDirect(cek, tokens.DIRECT, sharedkey)
	require.NoError(t, err)
	require.Equal(t, sharedkey, result.Bytes())
}

func TestKeyEncryptPBES2(t *testing.T) {
	cek := testCEK
	password := testPassword

	result, err := jwebb.KeyEncryptPBES2(cek, tokens.PBES2_HS256_A128KW, password)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEqual(t, cek, result.Bytes())
}

func TestKeyEncryptAESGCMKW(t *testing.T) {
	cek := testCEK
	sharedkey := testSharedKey16 // 16 bytes for A128GCMKW

	result, err := jwebb.KeyEncryptAESGCMKW(cek, tokens.A128GCMKW, sharedkey)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEqual(t, cek, result.Bytes())
}

func TestKeyEncryptRSA15(t *testing.T) {
	cek := testCEK

	// Generate RSA key pair
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)
	pubkey := &privkey.PublicKey

	result, err := jwebb.KeyEncryptRSA15(cek, tokens.RSA1_5, pubkey)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEqual(t, cek, result.Bytes())
}

func TestKeyEncryptRSAOAEP(t *testing.T) {
	cek := testCEK

	// Generate RSA key pair
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)
	pubkey := &privkey.PublicKey

	result, err := jwebb.KeyEncryptRSAOAEP(cek, tokens.RSA_OAEP, pubkey)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEqual(t, cek, result.Bytes())
}

func TestKeyEncryptECDHESCustom(t *testing.T) {
	cek := testCEK

	// Generate ECDSA key pair
	privkey, err := jwxtest.GenerateEcdsaKey(jwa.P256())
	require.NoError(t, err)

	gen, err := jwebb.NewECDHESKeyGenerator(&privkey.PublicKey)
	require.NoError(t, err)

	result, err := jwebb.KeyEncryptECDHESCustom(cek, tokens.ECDH_ES, testAPU, testAPV, gen, 16, tokens.A128GCM, false)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestContentEncryptionIsSupported(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		want bool
	}{
		{"A128GCM", tokens.A128GCM, true},
		{"A192GCM", tokens.A192GCM, true},
		{"A256GCM", tokens.A256GCM, true},
		{"A128CBC_HS256", tokens.A128CBC_HS256, true},
		{"A192CBC_HS384", tokens.A192CBC_HS384, true},
		{"A256CBC_HS512", tokens.A256CBC_HS512, true},
		invalidAlgTestCase,
		emptyAlgTestCase,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, jwebb.ContentEncryptionIsSupported(tt.alg))
		})
	}
}

func TestCreateContentCipher(t *testing.T) {
	supportedAlgs := []string{
		tokens.A128GCM,
		tokens.A192GCM,
		tokens.A256GCM,
		tokens.A128CBC_HS256,
		tokens.A192CBC_HS384,
		tokens.A256CBC_HS512,
	}

	for _, alg := range supportedAlgs {
		t.Run(alg, func(t *testing.T) {
			cipher, err := jwebb.CreateContentCipher(alg)
			require.NoError(t, err)
			require.NotNil(t, cipher)
		})
	}

	// Test unsupported algorithm
	_, err := jwebb.CreateContentCipher("invalid-alg")
	require.Error(t, err)
}
