package jwebb_test

import (
	"crypto/aes"
	"encoding/hex"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/stretchr/testify/require"
)

// RFC 3394 test vectors for key wrapping
type keyWrapVector struct {
	Kek      string
	Data     string
	Expected string
}

var rfc3394Vectors = []keyWrapVector{
	{
		Kek:      "000102030405060708090A0B0C0D0E0F",
		Data:     "00112233445566778899AABBCCDDEEFF",
		Expected: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
	},
	{
		Kek:      "000102030405060708090A0B0C0D0E0F1011121314151617",
		Data:     "00112233445566778899AABBCCDDEEFF",
		Expected: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
	},
	{
		Kek:      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		Data:     "00112233445566778899AABBCCDDEEFF0001020304050607",
		Expected: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
	},
}

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestRFC3394_Wrap(t *testing.T) {
	for _, v := range rfc3394Vectors {
		t.Logf("kek      = %s", v.Kek)
		t.Logf("data     = %s", v.Data)
		t.Logf("expected = %s", v.Expected)

		kek := mustHexDecode(v.Kek)
		data := mustHexDecode(v.Data)
		expected := mustHexDecode(v.Expected)

		block, err := aes.NewCipher(kek)
		require.NoError(t, err, "NewCipher is successful")
		out, err := jwebb.Wrap(block, data)
		require.NoError(t, err, "Wrap is successful")
		require.Equal(t, expected, out, "Wrap generates expected output")
		unwrapped, err := jwebb.Unwrap(block, out)
		require.NoError(t, err, "Unwrap is successful")
		require.Equal(t, data, unwrapped, "Unwrapped data matches")
	}
}

func TestKeyWrap(t *testing.T) {
	// Test vectors from: http://csrc.nist.gov/groups/ST/toolkit/documents/kms/key-wrap.pdf
	for i, v := range rfc3394Vectors {
		kek := mustHexDecode(v.Kek)
		cek := mustHexDecode(v.Data)
		expected := mustHexDecode(v.Expected)

		block, err := aes.NewCipher(kek)
		require.NoError(t, err)

		out, err := jwebb.Wrap(block, cek)
		require.NoError(t, err)
		require.Equal(t, expected, out, "output %d not as expected", i)

		unwrapped, err := jwebb.Unwrap(block, out)
		require.NoError(t, err)
		require.Equal(t, cek, unwrapped, "unwrap %d did not return original input", i)
	}
}
