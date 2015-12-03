package jwe

import (
	"crypto/aes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
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
		vector{
			Kek:      "000102030405060708090A0B0C0D0E0F",
			Data:     "00112233445566778899AABBCCDDEEFF",
			Expected: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		vector{
			Kek:      "000102030405060708090A0B0C0D0E0F1011121314151617",
			Data:     "00112233445566778899AABBCCDDEEFF",
			Expected: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
		},
		vector{
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
		if !assert.NoError(t, err, "NewCipher is successful") {
			return
		}
		out, err := keywrap(block, data)
		if !assert.NoError(t, err, "Wrap is successful") {
			return
		}

		if !assert.Equal(t, expected, out, "Wrap generates expected output") {
			return
		}

		unwrapped, err := keyunwrap(block, out)
		if !assert.NoError(t, err, "Unwrap is successful") {
			return
		}

		if !assert.Equal(t, data, unwrapped, "Unwrapped data matches") {
			return
		}
	}
}
