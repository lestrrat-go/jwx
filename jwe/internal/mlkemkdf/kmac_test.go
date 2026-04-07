package mlkemkdf

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test vectors from NIST SP 800-185 Section A.4 (KMAC samples).
// These are KMAC256 with specific K, X, L, S values.
func TestKMAC256(t *testing.T) {
	t.Run("SP800-185 Sample #4", func(t *testing.T) {
		// KMAC256 with:
		//   K = 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
		//       50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
		//   X = 00 01 02 03
		//   S = "My Tagged Application"
		//   L = 512 bits (64 bytes)
		key, _ := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
		x, _ := hex.DecodeString("00010203")
		s := "My Tagged Application"
		// Expected from OpenSSL test vectors (evpmac_common.txt) and BouncyCastle
		expected, _ := hex.DecodeString(
			"20C570C31346F703C9AC36C61C03CB64" +
				"C3970D0CFC787E9B79599D273A68D2F7" +
				"F69D4CC3DE9D104A351689F27CF6F595" +
				"1F0103F33F4F24871024D9C27773A8DD",
		)

		got := kmac256(key, x, 64, s)
		require.Equal(t, expected, got)
	})

	t.Run("SP800-185 Sample #5", func(t *testing.T) {
		// KMAC256 with:
		//   K = 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
		//       50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
		//   X = (200 bytes: 00 01 02 ... C7)
		//   S = ""
		//   L = 512 bits (64 bytes)
		key, _ := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
		x := make([]byte, 200)
		for i := range x {
			x[i] = byte(i)
		}
		expected, _ := hex.DecodeString(
			"75358CF39E41494E949707927CEE0AF2" +
				"0A3FF553904C86B08F21CC414BCFD691" +
				"589D27CF5E15369CBBFF8B9A4C2EB178" +
				"00855D0235FF635DA82533EC6B759B69",
		)

		got := kmac256(key, x, 64, "")
		require.Equal(t, expected, got)
	})
}

func TestLeftEncode(t *testing.T) {
	require.Equal(t, []byte{1, 0}, leftEncode(0))
	require.Equal(t, []byte{1, 1}, leftEncode(1))
	require.Equal(t, []byte{1, 255}, leftEncode(255))
	require.Equal(t, []byte{2, 1, 0}, leftEncode(256))
}

func TestRightEncode(t *testing.T) {
	require.Equal(t, []byte{0, 1}, rightEncode(0))
	require.Equal(t, []byte{1, 1}, rightEncode(1))
	require.Equal(t, []byte{255, 1}, rightEncode(255))
	require.Equal(t, []byte{1, 0, 2}, rightEncode(256))
}
