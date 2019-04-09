package jwe

import (
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/stretchr/testify/assert"
)

// This test uses Appendix 3 to verify some low level tools for
// KeyWrap and CBC HMAC encryption.
// This test uses a static cek so that we can validate the results
// against the contents in the above Appendix
func TestLowLevelParts_A128KW_A128CBCHS256(t *testing.T) {
	var plaintext = []byte{
		76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
		112, 114, 111, 115, 112, 101, 114, 46,
	}
	var cek = []byte{
		4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
		206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
		44, 207,
	}
	var iv = []byte{
		3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
		101,
	}
	var sharedkey = []byte{
		25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82,
	}
	var encsharedkey = []byte{
		232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216,
		22, 67, 201, 138, 193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3,
		76, 124, 193, 11, 98, 37, 173, 61, 104, 57,
	}
	var aad = []byte{
		101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
		83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
		77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
		110, 48,
	}
	var ciphertext = []byte{
		40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
		75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
		112, 56, 102,
	}
	var authtag = []byte{
		83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38,
		194, 85,
	}

	const compactExpected = `eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ`

	k, err := NewKeyWrapEncrypt(jwa.A128KW, sharedkey)
	if !assert.NoError(t, err, "Create key wrap") {
		return
	}

	enckey, err := k.KeyEncrypt(cek)
	if !assert.NoError(t, err, "Failed to encrypt key") {
		return
	}
	if !assert.Equal(t, encsharedkey, enckey.Bytes(), "encrypted keys match") {
		return
	}

	cipher, err := NewAesContentCipher(jwa.A128CBC_HS256)
	if !assert.NoError(t, err, "NewAesContentCipher is successful") {
		return
	}
	cipher.NonceGenerator = StaticKeyGenerate(iv)

	iv, encrypted, tag, err := cipher.encrypt(cek, plaintext, aad)
	if !assert.NoError(t, err, "encrypt() successful") {
		return
	}

	if !assert.Equal(t, ciphertext, encrypted, "Generated cipher text does not match") {
		return
	}

	if !assert.Equal(t, tag, authtag, "Generated tag text does not match") {
		return
	}

	data, err := cipher.decrypt(cek, iv, encrypted, tag, aad)
	if !assert.NoError(t, err, "decrypt successful") {
		return
	}

	if !assert.Equal(t, plaintext, data, "decrypt works") {
		return
	}

	r := NewRecipient()
	r.Header.Set("alg", jwa.A128KW)
	r.EncryptedKey = enckey.Bytes()

	protected := NewEncodedHeader()
	protected.Set("enc", jwa.A128CBC_HS256)

	msg := NewMessage()
	msg.ProtectedHeader = protected
	msg.AuthenticatedData = aad
	msg.CipherText = ciphertext
	msg.InitializationVector = iv
	msg.Tag = tag
	msg.Recipients = []Recipient{*r}

	serialized, err := CompactSerialize{}.Serialize(msg)
	if !assert.NoError(t, err, "compact serialization is successful") {
		return
	}

	if !assert.Equal(t, compactExpected, string(serialized), "compact serialization matches") {
		serialized, err = JSONSerialize{Pretty: true}.Serialize(msg)
		if !assert.NoError(t, err, "JSON serialization is successful") {
			return
		}
		t.Logf("%s", serialized)
	}
}
