// Code generated by tools/cmd/genjwa/main.go. DO NOT EDIT

package jwa_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

func TestKeyEncryptionAlgorithm(t *testing.T) {
	t.Parallel()
	t.Run(`accept jwa constant A128GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.A128GCMKW), `accept is successful`)
		require.Equal(t, jwa.A128GCMKW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string A128GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("A128GCMKW"), `accept is successful`)
		require.Equal(t, jwa.A128GCMKW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for A128GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "A128GCMKW"}), `accept is successful`)
		require.Equal(t, jwa.A128GCMKW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for A128GCMKW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A128GCMKW", jwa.A128GCMKW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.A128KW), `accept is successful`)
		require.Equal(t, jwa.A128KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("A128KW"), `accept is successful`)
		require.Equal(t, jwa.A128KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "A128KW"}), `accept is successful`)
		require.Equal(t, jwa.A128KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for A128KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A128KW", jwa.A128KW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant A192GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.A192GCMKW), `accept is successful`)
		require.Equal(t, jwa.A192GCMKW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string A192GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("A192GCMKW"), `accept is successful`)
		require.Equal(t, jwa.A192GCMKW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for A192GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "A192GCMKW"}), `accept is successful`)
		require.Equal(t, jwa.A192GCMKW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for A192GCMKW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A192GCMKW", jwa.A192GCMKW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.A192KW), `accept is successful`)
		require.Equal(t, jwa.A192KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("A192KW"), `accept is successful`)
		require.Equal(t, jwa.A192KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "A192KW"}), `accept is successful`)
		require.Equal(t, jwa.A192KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for A192KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A192KW", jwa.A192KW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant A256GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.A256GCMKW), `accept is successful`)
		require.Equal(t, jwa.A256GCMKW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string A256GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("A256GCMKW"), `accept is successful`)
		require.Equal(t, jwa.A256GCMKW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for A256GCMKW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "A256GCMKW"}), `accept is successful`)
		require.Equal(t, jwa.A256GCMKW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for A256GCMKW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A256GCMKW", jwa.A256GCMKW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.A256KW), `accept is successful`)
		require.Equal(t, jwa.A256KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("A256KW"), `accept is successful`)
		require.Equal(t, jwa.A256KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "A256KW"}), `accept is successful`)
		require.Equal(t, jwa.A256KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for A256KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "A256KW", jwa.A256KW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant DIRECT`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.DIRECT), `accept is successful`)
		require.Equal(t, jwa.DIRECT, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string dir`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("dir"), `accept is successful`)
		require.Equal(t, jwa.DIRECT, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for dir`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "dir"}), `accept is successful`)
		require.Equal(t, jwa.DIRECT, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for dir`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "dir", jwa.DIRECT.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant ECDH_ES`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.ECDH_ES), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string ECDH-ES`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("ECDH-ES"), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for ECDH-ES`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "ECDH-ES"}), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for ECDH-ES`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "ECDH-ES", jwa.ECDH_ES.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant ECDH_ES_A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.ECDH_ES_A128KW), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES_A128KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string ECDH-ES+A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("ECDH-ES+A128KW"), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES_A128KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for ECDH-ES+A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "ECDH-ES+A128KW"}), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES_A128KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for ECDH-ES+A128KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "ECDH-ES+A128KW", jwa.ECDH_ES_A128KW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant ECDH_ES_A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.ECDH_ES_A192KW), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES_A192KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string ECDH-ES+A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("ECDH-ES+A192KW"), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES_A192KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for ECDH-ES+A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "ECDH-ES+A192KW"}), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES_A192KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for ECDH-ES+A192KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "ECDH-ES+A192KW", jwa.ECDH_ES_A192KW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant ECDH_ES_A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.ECDH_ES_A256KW), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES_A256KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string ECDH-ES+A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("ECDH-ES+A256KW"), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES_A256KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for ECDH-ES+A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "ECDH-ES+A256KW"}), `accept is successful`)
		require.Equal(t, jwa.ECDH_ES_A256KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for ECDH-ES+A256KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "ECDH-ES+A256KW", jwa.ECDH_ES_A256KW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant PBES2_HS256_A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.PBES2_HS256_A128KW), `accept is successful`)
		require.Equal(t, jwa.PBES2_HS256_A128KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string PBES2-HS256+A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("PBES2-HS256+A128KW"), `accept is successful`)
		require.Equal(t, jwa.PBES2_HS256_A128KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for PBES2-HS256+A128KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "PBES2-HS256+A128KW"}), `accept is successful`)
		require.Equal(t, jwa.PBES2_HS256_A128KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for PBES2-HS256+A128KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "PBES2-HS256+A128KW", jwa.PBES2_HS256_A128KW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant PBES2_HS384_A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.PBES2_HS384_A192KW), `accept is successful`)
		require.Equal(t, jwa.PBES2_HS384_A192KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string PBES2-HS384+A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("PBES2-HS384+A192KW"), `accept is successful`)
		require.Equal(t, jwa.PBES2_HS384_A192KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for PBES2-HS384+A192KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "PBES2-HS384+A192KW"}), `accept is successful`)
		require.Equal(t, jwa.PBES2_HS384_A192KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for PBES2-HS384+A192KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "PBES2-HS384+A192KW", jwa.PBES2_HS384_A192KW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant PBES2_HS512_A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.PBES2_HS512_A256KW), `accept is successful`)
		require.Equal(t, jwa.PBES2_HS512_A256KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string PBES2-HS512+A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("PBES2-HS512+A256KW"), `accept is successful`)
		require.Equal(t, jwa.PBES2_HS512_A256KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for PBES2-HS512+A256KW`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "PBES2-HS512+A256KW"}), `accept is successful`)
		require.Equal(t, jwa.PBES2_HS512_A256KW, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for PBES2-HS512+A256KW`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "PBES2-HS512+A256KW", jwa.PBES2_HS512_A256KW.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant RSA1_5`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.RSA1_5), `accept is successful`)
		require.Equal(t, jwa.RSA1_5, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string RSA1_5`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("RSA1_5"), `accept is successful`)
		require.Equal(t, jwa.RSA1_5, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for RSA1_5`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "RSA1_5"}), `accept is successful`)
		require.Equal(t, jwa.RSA1_5, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for RSA1_5`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "RSA1_5", jwa.RSA1_5.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant RSA_OAEP`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.RSA_OAEP), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string RSA-OAEP`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("RSA-OAEP"), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for RSA-OAEP`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "RSA-OAEP"}), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for RSA-OAEP`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "RSA-OAEP", jwa.RSA_OAEP.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant RSA_OAEP_256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.RSA_OAEP_256), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP_256, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string RSA-OAEP-256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("RSA-OAEP-256"), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP_256, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for RSA-OAEP-256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "RSA-OAEP-256"}), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP_256, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for RSA-OAEP-256`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "RSA-OAEP-256", jwa.RSA_OAEP_256.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant RSA_OAEP_384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.RSA_OAEP_384), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP_384, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string RSA-OAEP-384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("RSA-OAEP-384"), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP_384, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for RSA-OAEP-384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "RSA-OAEP-384"}), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP_384, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for RSA-OAEP-384`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "RSA-OAEP-384", jwa.RSA_OAEP_384.String(), `stringified value matches`)
	})
	t.Run(`accept jwa constant RSA_OAEP_512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(jwa.RSA_OAEP_512), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP_512, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept the string RSA-OAEP-512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept("RSA-OAEP-512"), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP_512, dst, `accepted value should be equal to constant`)
	})
	t.Run(`accept fmt.Stringer for RSA-OAEP-512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.NoError(t, dst.Accept(stringer{src: "RSA-OAEP-512"}), `accept is successful`)
		require.Equal(t, jwa.RSA_OAEP_512, dst, `accepted value should be equal to constant`)
	})
	t.Run(`stringification for RSA-OAEP-512`, func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "RSA-OAEP-512", jwa.RSA_OAEP_512.String(), `stringified value matches`)
	})
	t.Run(`bail out on random integer value`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.Error(t, dst.Accept(1), `accept should fail`)
	})
	t.Run(`do not accept invalid (totally made up) string value`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.KeyEncryptionAlgorithm
		require.Error(t, dst.Accept(`totallyInvalidValue`), `accept should fail`)
	})
	t.Run(`check symmetric values`, func(t *testing.T) {
		t.Parallel()
		t.Run(`A128GCMKW`, func(t *testing.T) {
			require.True(t, jwa.A128GCMKW.IsSymmetric(), `jwa.A128GCMKW should be symmetric`)
		})
		t.Run(`A128KW`, func(t *testing.T) {
			require.True(t, jwa.A128KW.IsSymmetric(), `jwa.A128KW should be symmetric`)
		})
		t.Run(`A192GCMKW`, func(t *testing.T) {
			require.True(t, jwa.A192GCMKW.IsSymmetric(), `jwa.A192GCMKW should be symmetric`)
		})
		t.Run(`A192KW`, func(t *testing.T) {
			require.True(t, jwa.A192KW.IsSymmetric(), `jwa.A192KW should be symmetric`)
		})
		t.Run(`A256GCMKW`, func(t *testing.T) {
			require.True(t, jwa.A256GCMKW.IsSymmetric(), `jwa.A256GCMKW should be symmetric`)
		})
		t.Run(`A256KW`, func(t *testing.T) {
			require.True(t, jwa.A256KW.IsSymmetric(), `jwa.A256KW should be symmetric`)
		})
		t.Run(`DIRECT`, func(t *testing.T) {
			require.True(t, jwa.DIRECT.IsSymmetric(), `jwa.DIRECT should be symmetric`)
		})
		t.Run(`ECDH_ES`, func(t *testing.T) {
			require.False(t, jwa.ECDH_ES.IsSymmetric(), `jwa.ECDH_ES should NOT be symmetric`)
		})
		t.Run(`ECDH_ES_A128KW`, func(t *testing.T) {
			require.False(t, jwa.ECDH_ES_A128KW.IsSymmetric(), `jwa.ECDH_ES_A128KW should NOT be symmetric`)
		})
		t.Run(`ECDH_ES_A192KW`, func(t *testing.T) {
			require.False(t, jwa.ECDH_ES_A192KW.IsSymmetric(), `jwa.ECDH_ES_A192KW should NOT be symmetric`)
		})
		t.Run(`ECDH_ES_A256KW`, func(t *testing.T) {
			require.False(t, jwa.ECDH_ES_A256KW.IsSymmetric(), `jwa.ECDH_ES_A256KW should NOT be symmetric`)
		})
		t.Run(`PBES2_HS256_A128KW`, func(t *testing.T) {
			require.True(t, jwa.PBES2_HS256_A128KW.IsSymmetric(), `jwa.PBES2_HS256_A128KW should be symmetric`)
		})
		t.Run(`PBES2_HS384_A192KW`, func(t *testing.T) {
			require.True(t, jwa.PBES2_HS384_A192KW.IsSymmetric(), `jwa.PBES2_HS384_A192KW should be symmetric`)
		})
		t.Run(`PBES2_HS512_A256KW`, func(t *testing.T) {
			require.True(t, jwa.PBES2_HS512_A256KW.IsSymmetric(), `jwa.PBES2_HS512_A256KW should be symmetric`)
		})
		t.Run(`RSA1_5`, func(t *testing.T) {
			require.False(t, jwa.RSA1_5.IsSymmetric(), `jwa.RSA1_5 should NOT be symmetric`)
		})
		t.Run(`RSA_OAEP`, func(t *testing.T) {
			require.False(t, jwa.RSA_OAEP.IsSymmetric(), `jwa.RSA_OAEP should NOT be symmetric`)
		})
		t.Run(`RSA_OAEP_256`, func(t *testing.T) {
			require.False(t, jwa.RSA_OAEP_256.IsSymmetric(), `jwa.RSA_OAEP_256 should NOT be symmetric`)
		})
		t.Run(`RSA_OAEP_384`, func(t *testing.T) {
			require.False(t, jwa.RSA_OAEP_384.IsSymmetric(), `jwa.RSA_OAEP_384 should NOT be symmetric`)
		})
		t.Run(`RSA_OAEP_512`, func(t *testing.T) {
			require.False(t, jwa.RSA_OAEP_512.IsSymmetric(), `jwa.RSA_OAEP_512 should NOT be symmetric`)
		})
	})
	t.Run(`check list of elements`, func(t *testing.T) {
		t.Parallel()
		var expected = map[jwa.KeyEncryptionAlgorithm]struct{}{
			jwa.A128GCMKW:          {},
			jwa.A128KW:             {},
			jwa.A192GCMKW:          {},
			jwa.A192KW:             {},
			jwa.A256GCMKW:          {},
			jwa.A256KW:             {},
			jwa.DIRECT:             {},
			jwa.ECDH_ES:            {},
			jwa.ECDH_ES_A128KW:     {},
			jwa.ECDH_ES_A192KW:     {},
			jwa.ECDH_ES_A256KW:     {},
			jwa.PBES2_HS256_A128KW: {},
			jwa.PBES2_HS384_A192KW: {},
			jwa.PBES2_HS512_A256KW: {},
			jwa.RSA1_5:             {},
			jwa.RSA_OAEP:           {},
			jwa.RSA_OAEP_256:       {},
			jwa.RSA_OAEP_384:       {},
			jwa.RSA_OAEP_512:       {},
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
	customAlgorithm := jwa.KeyEncryptionAlgorithm("custom-algorithm")
	// Unregister the custom algorithm, in case tests fail.
	t.Cleanup(func() {
		jwa.UnregisterKeyEncryptionAlgorithm(customAlgorithm)
	})
	t.Run(`with custom algorithm registered`, func(t *testing.T) {
		jwa.RegisterKeyEncryptionAlgorithm(customAlgorithm)
		t.Run(`accept variable used to register custom algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.NoError(t, dst.Accept(customAlgorithm), `accept is successful`)
			require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`accept the string custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.NoError(t, dst.Accept(`custom-algorithm`), `accept is successful`)
			require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`accept fmt.Stringer for custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.NoError(t, dst.Accept(stringer{src: `custom-algorithm`}), `accept is successful`)
			require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`check symmetric`, func(t *testing.T) {
			t.Parallel()
			require.False(t, customAlgorithm.IsSymmetric(), `custom algorithm should NOT be symmetric`)
		})
	})
	t.Run(`with custom algorithm deregistered`, func(t *testing.T) {
		jwa.UnregisterKeyEncryptionAlgorithm(customAlgorithm)
		t.Run(`reject variable used to register custom algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.Error(t, dst.Accept(customAlgorithm), `accept failed`)
		})
		t.Run(`reject the string custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.Error(t, dst.Accept(`custom-algorithm`), `accept failed`)
		})
		t.Run(`reject fmt.Stringer for custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.Error(t, dst.Accept(stringer{src: `custom-algorithm`}), `accept failed`)
		})
		t.Run(`check symmetric`, func(t *testing.T) {
			t.Parallel()
			require.False(t, customAlgorithm.IsSymmetric(), `custom algorithm should NOT be symmetric`)
		})
	})

	t.Run(`with custom algorithm registered with WithSymmetricAlgorithm(false)`, func(t *testing.T) {
		jwa.RegisterKeyEncryptionAlgorithmWithOptions(customAlgorithm, jwa.WithSymmetricAlgorithm(false))
		t.Run(`accept variable used to register custom algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.NoError(t, dst.Accept(customAlgorithm), `accept is successful`)
			require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`accept the string custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.NoError(t, dst.Accept(`custom-algorithm`), `accept is successful`)
			require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`accept fmt.Stringer for custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.NoError(t, dst.Accept(stringer{src: `custom-algorithm`}), `accept is successful`)
			require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`check symmetric`, func(t *testing.T) {
			t.Parallel()
			require.False(t, customAlgorithm.IsSymmetric(), `custom algorithm should NOT be symmetric`)
		})
	})
	t.Run(`with custom algorithm deregistered (was WithSymmetricAlgorithm(false))`, func(t *testing.T) {
		jwa.UnregisterKeyEncryptionAlgorithm(customAlgorithm)
		t.Run(`reject variable used to register custom algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.Error(t, dst.Accept(customAlgorithm), `accept failed`)
		})
		t.Run(`reject the string custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.Error(t, dst.Accept(`custom-algorithm`), `accept failed`)
		})
		t.Run(`reject fmt.Stringer for custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.Error(t, dst.Accept(stringer{src: `custom-algorithm`}), `accept failed`)
		})
		t.Run(`check symmetric`, func(t *testing.T) {
			t.Parallel()
			require.False(t, customAlgorithm.IsSymmetric(), `custom algorithm should NOT be symmetric`)
		})
	})

	t.Run(`with custom algorithm registered with WithSymmetricAlgorithm(true)`, func(t *testing.T) {
		jwa.RegisterKeyEncryptionAlgorithmWithOptions(customAlgorithm, jwa.WithSymmetricAlgorithm(true))
		t.Run(`accept variable used to register custom algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.NoError(t, dst.Accept(customAlgorithm), `accept is successful`)
			require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`accept the string custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.NoError(t, dst.Accept(`custom-algorithm`), `accept is successful`)
			require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`accept fmt.Stringer for custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.NoError(t, dst.Accept(stringer{src: `custom-algorithm`}), `accept is successful`)
			require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`check symmetric`, func(t *testing.T) {
			t.Parallel()
			require.True(t, customAlgorithm.IsSymmetric(), `custom algorithm should be symmetric`)
		})
	})
	t.Run(`with custom algorithm deregistered (was WithSymmetricAlgorithm(true))`, func(t *testing.T) {
		jwa.UnregisterKeyEncryptionAlgorithm(customAlgorithm)
		t.Run(`reject variable used to register custom algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.Error(t, dst.Accept(customAlgorithm), `accept failed`)
		})
		t.Run(`reject the string custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.Error(t, dst.Accept(`custom-algorithm`), `accept failed`)
		})
		t.Run(`reject fmt.Stringer for custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.KeyEncryptionAlgorithm
			require.Error(t, dst.Accept(stringer{src: `custom-algorithm`}), `accept failed`)
		})
		t.Run(`check symmetric`, func(t *testing.T) {
			t.Parallel()
			require.False(t, customAlgorithm.IsSymmetric(), `custom algorithm should NOT be symmetric`)
		})
	})
}
