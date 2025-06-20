package jwebb_test

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwe/jwebb"
	"github.com/stretchr/testify/require"
)

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type vector struct {
	Kek      string
	Data     string
	Expected string
}

func TestRFC3394_Wrap(t *testing.T) {
	vectors := []vector{
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

	for _, v := range vectors {
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
	// stolen from go-jose
	// Test vectors from: http://csrc.nist.gov/groups/ST/toolkit/documents/kms/key-wrap.pdf
	kek0, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	cek0, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")

	expected0, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	kek1, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F1011121314151617")
	cek1, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")

	expected1, _ := hex.DecodeString("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")

	kek2, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	cek2, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF0001020304050607")

	expected2, _ := hex.DecodeString("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")

	block0, _ := aes.NewCipher(kek0)
	block1, _ := aes.NewCipher(kek1)
	block2, _ := aes.NewCipher(kek2)

	out0, _ := jwebb.Wrap(block0, cek0)
	out1, _ := jwebb.Wrap(block1, cek1)
	out2, _ := jwebb.Wrap(block2, cek2)

	if !bytes.Equal(out0, expected0) {
		t.Error("output 0 not as expected, got", out0, "wanted", expected0)
	}

	if !bytes.Equal(out1, expected1) {
		t.Error("output 1 not as expected, got", out1, "wanted", expected1)
	}

	if !bytes.Equal(out2, expected2) {
		t.Error("output 2 not as expected, got", out2, "wanted", expected2)
	}

	unwrap0, _ := jwebb.Unwrap(block0, out0)
	unwrap1, _ := jwebb.Unwrap(block1, out1)
	unwrap2, _ := jwebb.Unwrap(block2, out2)

	if !bytes.Equal(unwrap0, cek0) {
		t.Error("key unwrap did not return original input, got", unwrap0, "wanted", cek0)
	}

	if !bytes.Equal(unwrap1, cek1) {
		t.Error("key unwrap did not return original input, got", unwrap1, "wanted", cek1)
	}

	if !bytes.Equal(unwrap2, cek2) {
		t.Error("key unwrap did not return original input, got", unwrap2, "wanted", cek2)
	}
}