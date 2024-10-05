// Code generated by tools/cmd/genjwa/main.go. DO NOT EDIT

package jwa_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

func TestKeyEncryptionAlgorithm(t *testing.T) {
	t.Parallel()
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("A128GCMKW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.A128GCMKW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string A128GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("A128GCMKW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.A128GCMKW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for A128GCMKW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A128GCMKW", jwa.A128GCMKW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("A128KW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.A128KW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("A128KW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.A128KW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for A128KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A128KW", jwa.A128KW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("A192GCMKW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.A192GCMKW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string A192GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("A192GCMKW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.A192GCMKW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for A192GCMKW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A192GCMKW", jwa.A192GCMKW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("A192KW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.A192KW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("A192KW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.A192KW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for A192KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A192KW", jwa.A192KW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("A256GCMKW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.A256GCMKW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string A256GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("A256GCMKW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.A256GCMKW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for A256GCMKW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A256GCMKW", jwa.A256GCMKW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("A256KW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.A256KW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("A256KW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.A256KW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for A256KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A256KW", jwa.A256KW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("dir")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.DIRECT(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string dir`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("dir"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.DIRECT(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for dir`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "dir", jwa.DIRECT().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("ECDH-ES")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.ECDH_ES(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string ECDH-ES`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("ECDH-ES"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.ECDH_ES(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for ECDH-ES`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "ECDH-ES", jwa.ECDH_ES().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("ECDH-ES+A128KW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.ECDH_ES_A128KW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string ECDH-ES+A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("ECDH-ES+A128KW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.ECDH_ES_A128KW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for ECDH-ES+A128KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "ECDH-ES+A128KW", jwa.ECDH_ES_A128KW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("ECDH-ES+A192KW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.ECDH_ES_A192KW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string ECDH-ES+A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("ECDH-ES+A192KW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.ECDH_ES_A192KW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for ECDH-ES+A192KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "ECDH-ES+A192KW", jwa.ECDH_ES_A192KW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("ECDH-ES+A256KW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.ECDH_ES_A256KW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string ECDH-ES+A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("ECDH-ES+A256KW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.ECDH_ES_A256KW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for ECDH-ES+A256KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "ECDH-ES+A256KW", jwa.ECDH_ES_A256KW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("PBES2-HS256+A128KW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.PBES2_HS256_A128KW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string PBES2-HS256+A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("PBES2-HS256+A128KW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.PBES2_HS256_A128KW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for PBES2-HS256+A128KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "PBES2-HS256+A128KW", jwa.PBES2_HS256_A128KW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("PBES2-HS384+A192KW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.PBES2_HS384_A192KW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string PBES2-HS384+A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("PBES2-HS384+A192KW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.PBES2_HS384_A192KW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for PBES2-HS384+A192KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "PBES2-HS384+A192KW", jwa.PBES2_HS384_A192KW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("PBES2-HS512+A256KW")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.PBES2_HS512_A256KW(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string PBES2-HS512+A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("PBES2-HS512+A256KW"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.PBES2_HS512_A256KW(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for PBES2-HS512+A256KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "PBES2-HS512+A256KW", jwa.PBES2_HS512_A256KW().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("RSA1_5")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.RSA1_5(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string RSA1_5`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("RSA1_5"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.RSA1_5(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for RSA1_5`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "RSA1_5", jwa.RSA1_5().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("RSA-OAEP")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.RSA_OAEP(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string RSA-OAEP`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("RSA-OAEP"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.RSA_OAEP(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for RSA-OAEP`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "RSA-OAEP", jwa.RSA_OAEP().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("RSA-OAEP-256")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.RSA_OAEP_256(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string RSA-OAEP-256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("RSA-OAEP-256"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.RSA_OAEP_256(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for RSA-OAEP-256`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "RSA-OAEP-256", jwa.RSA_OAEP_256().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("RSA-OAEP-384")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.RSA_OAEP_384(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string RSA-OAEP-384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("RSA-OAEP-384"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.RSA_OAEP_384(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for RSA-OAEP-384`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "RSA-OAEP-384", jwa.RSA_OAEP_384().String(), `stringified value matches`)
	})
	t.Run(`Lookup the object`, func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupKeyEncryptionAlgorithm("RSA-OAEP-512")
		require.True(t, ok, `Lookup should succeed`)
		require.Equal(t, jwa.RSA_OAEP_512(), v, `Lookup value should be equal to constant`)
	})
	t.Run(`Unmarhal the string RSA-OAEP-512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, json.Unmarshal([]byte("RSA-OAEP-512"), &dst), `UnmarshalJSON is successful`)
		require.Equal(t, jwa.RSA_OAEP_512(), dst, `unmarshaled value should be equal to constant`)
	})
	t.Run(`stringification for RSA-OAEP-512`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "RSA-OAEP-512", jwa.RSA_OAEP_512().String(), `stringified value matches`)
	})
	t.Run(`Unmarshal should fail for invalid value (totally made up) string value`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.Error(t, json.Unmarshal([]byte(`totallyInvalidValue`), &dst), `Unmarshal should fail`)
	})
	t.Run(`check symmetric values`, func(t *testing.T) {
		t.Parallel()
		t.Run(`A128GCMKW`, func(t *testing.T) {
			require.True(t, jwa.A128GCMKW().IsSymmetric(), `jwa.A128GCMKW returns expected value`)
		})
		t.Run(`A128KW`, func(t *testing.T) {
			require.True(t, jwa.A128KW().IsSymmetric(), `jwa.A128KW returns expected value`)
		})
		t.Run(`A192GCMKW`, func(t *testing.T) {
			require.True(t, jwa.A192GCMKW().IsSymmetric(), `jwa.A192GCMKW returns expected value`)
		})
		t.Run(`A192KW`, func(t *testing.T) {
			require.True(t, jwa.A192KW().IsSymmetric(), `jwa.A192KW returns expected value`)
		})
		t.Run(`A256GCMKW`, func(t *testing.T) {
			require.True(t, jwa.A256GCMKW().IsSymmetric(), `jwa.A256GCMKW returns expected value`)
		})
		t.Run(`A256KW`, func(t *testing.T) {
			require.True(t, jwa.A256KW().IsSymmetric(), `jwa.A256KW returns expected value`)
		})
		t.Run(`DIRECT`, func(t *testing.T) {
			require.True(t, jwa.DIRECT().IsSymmetric(), `jwa.DIRECT returns expected value`)
		})
		t.Run(`ECDH_ES`, func(t *testing.T) {
			require.False(t, jwa.ECDH_ES().IsSymmetric(), `jwa.ECDH_ES returns expected value`)
		})
		t.Run(`ECDH_ES_A128KW`, func(t *testing.T) {
			require.False(t, jwa.ECDH_ES_A128KW().IsSymmetric(), `jwa.ECDH_ES_A128KW returns expected value`)
		})
		t.Run(`ECDH_ES_A192KW`, func(t *testing.T) {
			require.False(t, jwa.ECDH_ES_A192KW().IsSymmetric(), `jwa.ECDH_ES_A192KW returns expected value`)
		})
		t.Run(`ECDH_ES_A256KW`, func(t *testing.T) {
			require.False(t, jwa.ECDH_ES_A256KW().IsSymmetric(), `jwa.ECDH_ES_A256KW returns expected value`)
		})
		t.Run(`PBES2_HS256_A128KW`, func(t *testing.T) {
			require.True(t, jwa.PBES2_HS256_A128KW().IsSymmetric(), `jwa.PBES2_HS256_A128KW returns expected value`)
		})
		t.Run(`PBES2_HS384_A192KW`, func(t *testing.T) {
			require.True(t, jwa.PBES2_HS384_A192KW().IsSymmetric(), `jwa.PBES2_HS384_A192KW returns expected value`)
		})
		t.Run(`PBES2_HS512_A256KW`, func(t *testing.T) {
			require.True(t, jwa.PBES2_HS512_A256KW().IsSymmetric(), `jwa.PBES2_HS512_A256KW returns expected value`)
		})
		t.Run(`RSA1_5`, func(t *testing.T) {
			require.False(t, jwa.RSA1_5().IsSymmetric(), `jwa.RSA1_5 returns expected value`)
		})
		t.Run(`RSA_OAEP`, func(t *testing.T) {
			require.False(t, jwa.RSA_OAEP().IsSymmetric(), `jwa.RSA_OAEP returns expected value`)
		})
		t.Run(`RSA_OAEP_256`, func(t *testing.T) {
			require.False(t, jwa.RSA_OAEP_256().IsSymmetric(), `jwa.RSA_OAEP_256 returns expected value`)
		})
		t.Run(`RSA_OAEP_384`, func(t *testing.T) {
			require.False(t, jwa.RSA_OAEP_384().IsSymmetric(), `jwa.RSA_OAEP_384 returns expected value`)
		})
		t.Run(`RSA_OAEP_512`, func(t *testing.T) {
			require.False(t, jwa.RSA_OAEP_512().IsSymmetric(), `jwa.RSA_OAEP_512 returns expected value`)
		})
	})
	t.Run(`check list of elements`, func(t *testing.T) {
		t.Parallel()
		var expected = map[jwa.KeyEncryptionAlgorithm]struct{}{
			jwa.A128GCMKW():          {},
			jwa.A128KW():             {},
			jwa.A192GCMKW():          {},
			jwa.A192KW():             {},
			jwa.A256GCMKW():          {},
			jwa.A256KW():             {},
			jwa.DIRECT():             {},
			jwa.ECDH_ES():            {},
			jwa.ECDH_ES_A128KW():     {},
			jwa.ECDH_ES_A192KW():     {},
			jwa.ECDH_ES_A256KW():     {},
			jwa.PBES2_HS256_A128KW(): {},
			jwa.PBES2_HS384_A192KW(): {},
			jwa.PBES2_HS512_A256KW(): {},
			jwa.RSA1_5():             {},
			jwa.RSA_OAEP():           {},
			jwa.RSA_OAEP_256():       {},
			jwa.RSA_OAEP_384():       {},
			jwa.RSA_OAEP_512():       {},
		}
		for _, v := range jwa.KeyEncryptionAlgorithms() {
			_, ok := expected[v]
			require.True(t, ok, `%s should be in the expected list`, v)
			delete(expected, v)
		}
		require.Len(t, expected, 0)
	})
}

// Note: this test can NOT be run in parallel as it uses options with global effect.
func TestKeyEncryptionAlgorithmCustomAlgorithm(t *testing.T) {
	// These subtests can NOT be run in parallel as options with global effect change.
	const customAlgorithmValue = `custom-algorithm`
	for _, symmetric := range []bool{true, false} {
		customAlgorithm := jwa.NewKeyEncryptionAlgorithm(customAlgorithmValue, jwa.WithIsSymmetric(symmetric))
		// Unregister the custom algorithm, in case tests fail.
		t.Cleanup(func() {
			jwa.UnregisterKeyEncryptionAlgorithm(customAlgorithm)
		})
		t.Run(`with custom algorithm registered`, func(t *testing.T) {
			jwa.RegisterKeyEncryptionAlgorithm(customAlgorithm)
			t.Run(`Lookup the object`, func(t *testing.T) {
				t.Parallel()
				v, ok := jwa.LookupKeyEncryptionAlgorithm(customAlgorithmValue)
				require.True(t, ok, `Lookup should succeed`)
				require.Equal(t, customAlgorithm, v, `Lookup value should be equal to constant`)
			})
			t.Run(`Unmarshal custom algorithm`, func(t *testing.T) {
				t.Parallel()
				var dst jwa.KeyEncryptionAlgorithm
				require.NoError(t, json.Unmarshal([]byte(customAlgorithmValue), &dst), `Unmarshal is successful`)
				require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
			})
			t.Run(`check symmetric`, func(t *testing.T) {
				t.Parallel()
				require.Equal(t, symmetric, customAlgorithm.IsSymmetric(), `custom algorithm's symmetric attribute should match`)
			})
		})
		t.Run(`with custom algorithm deregistered`, func(t *testing.T) {
			jwa.UnregisterKeyEncryptionAlgorithm(customAlgorithm)
			t.Run(`Lookup the object`, func(t *testing.T) {
				t.Parallel()
				_, ok := jwa.LookupKeyEncryptionAlgorithm(customAlgorithmValue)
				require.False(t, ok, `Lookup should fail`)
			})
			t.Run(`Unmarshal custom algorithm`, func(t *testing.T) {
				t.Parallel()
				var dst jwa.KeyEncryptionAlgorithm
				require.Error(t, json.Unmarshal([]byte(customAlgorithmValue), &dst), `Unmarshal should fail`)
			})
		})
	}
}
