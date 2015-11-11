package jwe

import (
	"testing"

	"github.com/lestrrat/go-jwx/internal/rsautil"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/stretchr/testify/assert"
)

const examplePayload = `The true sign of intelligence is not knowledge but imagination.`

func TestSanityCheck_JWEExamplePayload(t *testing.T) {
	expected := []byte{
		84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
		111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
		101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
		101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
		110, 97, 116, 105, 111, 110, 46,
	}
	assert.Equal(t, expected, []byte(examplePayload), "examplePayload OK")
}

func TestParse_Compact(t *testing.T) {
	s := `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ`

	msg, err := Parse([]byte(s))
	if !assert.NoError(t, err, "Parsing JWE is successful") {
		return
	}

	if !assert.Len(t, msg.Recipients, 1, "There is exactly 1 recipient") {
		return
	}
}

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

	k, err := NewAesKeyWrap(jwa.A128KW, sharedkey)
	if !assert.NoError(t, err, "Create key wrap") {
		return
	}

	enckey, err := k.KeyEncrypt(cek)
	if !assert.NoError(t, err, "Failed to encrypt key") {
		return
	}
	if !assert.Equal(t, encsharedkey, enckey, "encrypted keys match") {
		return
	}

	cipher, err := NewAesContentCipher(jwa.A128CBC_HS256)
	if !assert.NoError(t, err, "NewAesContentCipher is successful") {
		return
	}

	encrypted, tag, err := cipher.encrypt(cek, iv, plaintext, aad)
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
	r.EncryptedKey = enckey

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
		t.Logf("%#s", serialized)
	}
}

// This test parses the example found in https://tools.ietf.org/html/rfc7516#appendix-A.1,
// and checks if we can roundtrip to the same compact serialization format.
func TestParse_RSAES_OAEP_AES_GCM(t *testing.T) {
	const payload = `The true sign of intelligence is not knowledge but imagination.`
	const serialized = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ`
	var jwkstr = []byte(`
     {"kty":"RSA",
      "n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
      "e":"AQAB",
      "d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
      "p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
      "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
      "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
      "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
      "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
     }`)
	privkey, err := rsautil.PrivateKeyFromJSON(jwkstr)
	if !assert.NoError(t, err, "PrivateKey created") {
		return
	}

	msg, err := ParseString(serialized)
	if !assert.NoError(t, err, "parse successful") {
		return
	}

	// Test decrypting?
	plaintext, err := DecryptMessage(msg, privkey)
	if !assert.NoError(t, err, "Decrypt message succeeded") {
		return
	}

	if !assert.Equal(t, payload, string(plaintext), "decrypted value does not match") {
		return
	}

	jsonbuf, err := CompactSerialize{}.Serialize(msg)
	if !assert.NoError(t, err, "Compact serialize succeeded") {
		return
	}

	if !assert.Equal(t, serialized, string(jsonbuf), "Compact serialize matches") {
		jsonbuf, _ = JSONSerialize{Pretty: true}.Serialize(msg)
		t.Logf("%s", jsonbuf)
		return
	}
}

// https://tools.ietf.org/html/rfc7516#appendix-A.1. Note that cek is dynamically
// generated, so the encrypted values will NOT match that of the RFC.
func TestEncode_RSAES_OAEP_AES_GCM(t *testing.T) {
	var plaintext = []byte{
		84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
		111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
		101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
		101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
		110, 97, 116, 105, 111, 110, 46,
	}
	var aad = []byte{
		101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
		116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
		54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81,
	}
	var jwkstr = []byte(`
     {"kty":"RSA",
      "n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
      "e":"AQAB",
      "d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
      "p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
      "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
      "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
      "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
      "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
     }`)
	privkey, err := rsautil.PrivateKeyFromJSON(jwkstr)
	if !assert.NoError(t, err, "PrivateKey created") {
		return
	}
	_ = privkey

	c, err := NewAesCrypt(jwa.A128GCM, []byte{})
	if !assert.NoError(t, err, "NewCrypt successful") {
		return
	}

	cek, iv, ciphertext, tag, err := c.Encrypt(plaintext, aad)
	if !assert.NoError(t, err, "Failed to encrypt data") {
		return
	}

	data, err := c.Decrypt(cek, iv, ciphertext, tag, aad)
	if !assert.NoError(t, err, "Decrypt successful") {
		return
	}

	if !assert.Equal(t, plaintext, data, "roundtrip gives us the same data") {
		return
	}
}

// https://tools.ietf.org/html/rfc7516#appendix-A.3. Note that cek is dynamically
// generated, so the encrypted values will NOT match that of the RFC.
func TestEncode_A128KW_A128CBCHS256(t *testing.T) {
	var plaintext = []byte{
		76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
		112, 114, 111, 115, 112, 101, 114, 46,
	}
	var aad = []byte{
		101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
		83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
		77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
		110, 48,
	}
	var sharedkey = []byte{
		25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82,
	}

	c, err := NewAesCrypt(jwa.A128CBC_HS256, []byte("hello, world!"))
	if !assert.NoError(t, err, "NewCrypt is successful") {
		return
	}

	k, err := NewAesKeyWrap(jwa.A128KW, sharedkey)
	if !assert.NoError(t, err, "Create key wrap") {
		return
	}

	kg := NewRandomKeyGenerate(c.KeySize() * 2)

	e := NewEncrypt(c, kg, k)

	msg, err := e.Encrypt(plaintext, aad)
	if !assert.NoError(t, err, "BuildMessage successful") {
		return
	}
	_ = msg

	cek, iv, ciphertext, tag, err := c.Encrypt(plaintext, aad)
	if !assert.NoError(t, err, "Failed to encrypt data") {
		return
	}

	data, err := c.Decrypt(cek, iv, ciphertext, tag, aad)
	if !assert.NoError(t, err, "Decrypt successful") {
		return
	}

	if !assert.Equal(t, plaintext, data, "roundtrip gives us the same data") {
		return
	}
}
