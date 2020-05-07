package jwe_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

const (
	examplePayload = `The true sign of intelligence is not knowledge but imagination.`
)

var rsaPrivKey rsa.PrivateKey

func init() {
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

	privkey := jwk.NewRSAPrivateKey()
	if err := json.Unmarshal(jwkstr, privkey); err != nil {
		panic(err)
	}

	if err := privkey.Raw(&rsaPrivKey); err != nil {
		panic(err)
	}
}

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

func TestParse(t *testing.T) {
	const s = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ`
	t.Run("Compact format", func(t *testing.T) {
		t.Run("Normal", func(t *testing.T) {
			msg, err := jwe.Parse([]byte(s))
			if !assert.NoError(t, err, "Parsing JWE is successful") {
				return
			}

			if !assert.Len(t, msg.Recipients(), 1, "There is exactly 1 recipient") {
				return
			}
		})

		parts := strings.Split(s, ".")
		t.Run("Missing parts", func(t *testing.T) {
			s2 := strings.Join(parts[:4], ".")
			_, err := jwe.Parse([]byte(s2))
			if !assert.Error(t, err, `should fail to parse compact format with missing parts`) {
				return
			}
		})
		t.Run("Invalid header", func(t *testing.T) {
			s2 := strings.Join(append(append([]string(nil), "!!invalidheader!!"), parts[1:]...), ".")
			_, err := jwe.Parse([]byte(s2))
			if !assert.Error(t, err, `should fail to parse compact format with invalid header`) {
				return
			}
		})
		t.Run("Invalid encrypted key", func(t *testing.T) {
			s2 := strings.Join(append(append(append([]string(nil), parts[0]), "!!invalidenckey!!"), parts[2:]...), ".")
			_, err := jwe.Parse([]byte(s2))
			if !assert.Error(t, err, `should fail to parse compact format with invalid encrypted key`) {
				return
			}
		})
		t.Run("Invalid initialization vector", func(t *testing.T) {
			s2 := strings.Join(append(append(append([]string(nil), parts[:2]...), "!!invalidiv!!"), parts[3:]...), ".")
			_, err := jwe.Parse([]byte(s2))
			if !assert.Error(t, err, `should fail to parse compact format with invalid initialization vector`) {
				return
			}
		})
		t.Run("Invalid content", func(t *testing.T) {
			s2 := strings.Join(append(append(append([]string(nil), parts[:3]...), "!!invalidcontent!!"), parts[4:]...), ".")
			_, err := jwe.Parse([]byte(s2))
			if !assert.Error(t, err, `should fail to parse compact format with invalid content`) {
				return
			}
		})
		t.Run("Invalid tag", func(t *testing.T) {
			s2 := strings.Join(append(parts[:4], "!!invalidtag!!"), ".")
			_, err := jwe.Parse([]byte(s2))
			if !assert.Error(t, err, `should fail to parse compact format with invalid tag`) {
				return
			}
		})
	})
	t.Run("JSON format", func(t *testing.T) {
		msg, err := jwe.Parse([]byte(s))
		if !assert.NoError(t, err, "Parsing JWE is successful") {
			return
		}

		buf, err := jwe.JSON(msg)
		if !assert.NoError(t, err, "Serializing to JSON format should succeed") {
			return
		}

		msg2, err := jwe.Parse(buf)
		if !assert.NoError(t, err, "Parsing JWE in JSON format should succeed") {
			return
		}

		if !assert.Equal(t, msg, msg2, "messages should match") {
			return
		}
	})
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

	privkey := jwk.NewRSAPrivateKey()
	if !assert.NoError(t, json.Unmarshal(jwkstr, privkey), `parsing jwk should succeed`) {
		return
	}

	var rawkey rsa.PrivateKey
	if !assert.NoError(t, privkey.Raw(&rawkey), `obtaining raw key should succeed`) {
		return
	}

	msg, err := jwe.ParseString(serialized)
	if !assert.NoError(t, err, "parse successful") {
		return
	}

	if !assert.Equal(t, 1, len(msg.Recipients()), "message recipients header length is 1") {
		return
	}

	_, ok := msg.Recipients()[0].Headers().Get(jwe.ContentEncryptionKey)
	if !assert.Equal(t, false, ok, "no content encryption key in message recipients header") {
		return
	}

	plaintext, err := msg.Decrypt(jwa.RSA_OAEP, rawkey)
	if !assert.NoError(t, err, "Decrypt message succeeded") {
		return
	}

	if !assert.Equal(t, payload, string(plaintext), "decrypted value does not match") {
		return
	}

	serializers := []struct {
		Name     string
		Func     func(*jwe.Message) ([]byte, error)
		Expected string
	}{
		{
			Name:     "Compact",
			Func:     func(m *jwe.Message) ([]byte, error) { return jwe.Compact(m) },
			Expected: serialized,
		},
		{
			Name:     "JSON",
			Func:     func(m *jwe.Message) ([]byte, error) { return jwe.JSON(m) },
			Expected: `{"aad":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","ciphertext":"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A","iv":"48V1_ALb6US04U3b","protected":"eyJlbmMiOiJBMjU2R0NNIn0","recipients":[{"header":{"alg":"RSA-OAEP"},"encrypted_key":"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg"}],"tag":"XFBoMYUZodetZdvTiFvSkQ"}`,
		},
		{
			Name: "JSON (Pretty)",
			Func: func(m *jwe.Message) ([]byte, error) { return jwe.JSON(m, jwe.WithPrettyJSONFormat(true)) },
			Expected: `{
  "aad": "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ",
  "ciphertext": "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A",
  "iv": "48V1_ALb6US04U3b",
  "protected": "eyJlbmMiOiJBMjU2R0NNIn0",
  "recipients": [
    {
      "header": {
        "alg": "RSA-OAEP"
      },
      "encrypted_key": "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg"
    }
  ],
  "tag": "XFBoMYUZodetZdvTiFvSkQ"
}`,
		},
	}

	for _, serializer := range serializers {
		serializer := serializer
		for _, compression := range []jwa.CompressionAlgorithm{jwa.NoCompress, jwa.Deflate} {
			compression := compression
			t.Run(serializer.Name+" (compression="+compression.String()+")", func(t *testing.T) {
				jsonbuf, err := serializer.Func(msg)
				if !assert.NoError(t, err, "serialize succeeded") {
					return
				}

				if !assert.Equal(t, serializer.Expected, string(jsonbuf), "serialize result matches") {
					jsonbuf, _ = jwe.JSON(msg, jwe.WithPrettyJSONFormat(true))
					t.Logf("%s", jsonbuf)
					return
				}

				encrypted, err := jwe.Encrypt(plaintext, jwa.RSA_OAEP, rawkey.PublicKey, jwa.A256GCM, compression)
				if !assert.NoError(t, err, "jwe.Encrypt should succeed") {
					return
				}

				plaintext, err = jwe.Decrypt(encrypted, jwa.RSA_OAEP, rawkey)
				if !assert.NoError(t, err, "jwe.Decrypt should succeed") {
					return
				}

				if !assert.Equal(t, payload, string(plaintext), "jwe.Decrypt should produce the same plaintext") {
					return
				}
			})
		}
	}

	// Test direct marshaling and unmarshaling
	t.Run("Marshal/Unmarshal", func(t *testing.T) {
		buf, err := json.Marshal(msg)
		if !assert.NoError(t, err, `json.Marshal should succeed`) {
			return
		}

		m2 := jwe.NewMessage()
		if !assert.NoError(t, json.Unmarshal(buf, m2), `json.Unmarshal should succeed`) {
			t.Logf("%s", buf)
			return
		}

		if !assert.Equal(t, msg, m2, `messages should be the same after roundtrip`) {
			return
		}
	})
}

// https://tools.ietf.org/html/rfc7516#appendix-A.1.
func TestRoundtrip_RSAES_OAEP_AES_GCM(t *testing.T) {
	var plaintext = []byte{
		84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
		111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
		101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
		101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
		110, 97, 116, 105, 111, 110, 46,
	}

	max := 100
	if testing.Short() {
		max = 1
	}

	for i := 0; i < max; i++ {
		encrypted, err := jwe.Encrypt(plaintext, jwa.RSA_OAEP, &rsaPrivKey.PublicKey, jwa.A256GCM, jwa.NoCompress)
		if !assert.NoError(t, err, "Encrypt should succeed") {
			return
		}

		decrypted, err := jwe.Decrypt(encrypted, jwa.RSA_OAEP, rsaPrivKey)
		if !assert.NoError(t, err, "Decrypt should succeed") {
			return
		}

		if !assert.Equal(t, plaintext, decrypted, "Decrypted content should match") {
			return
		}
	}
}

func TestRoundtrip_RSA1_5_A128CBC_HS256(t *testing.T) {
	var plaintext = []byte{
		76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
		112, 114, 111, 115, 112, 101, 114, 46,
	}

	max := 100
	if testing.Short() {
		max = 1
	}

	for i := 0; i < max; i++ {
		encrypted, err := jwe.Encrypt(plaintext, jwa.RSA1_5, &rsaPrivKey.PublicKey, jwa.A128CBC_HS256, jwa.NoCompress)
		if !assert.NoError(t, err, "Encrypt is successful") {
			return
		}

		decrypted, err := jwe.Decrypt(encrypted, jwa.RSA1_5, rsaPrivKey)
		if !assert.NoError(t, err, "Decrypt successful") {
			return
		}

		if !assert.Equal(t, plaintext, decrypted, "Decrypted correct plaintext") {
			return
		}
	}
}

// https://tools.ietf.org/html/rfc7516#appendix-A.3. Note that cek is dynamically
// generated, so the encrypted values will NOT match that of the RFC.
func TestEncode_A128KW_A128CBC_HS256(t *testing.T) {
	var plaintext = []byte{
		76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
		112, 114, 111, 115, 112, 101, 114, 46,
	}
	var sharedkey = []byte{
		25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82,
	}

	max := 100
	if testing.Short() {
		max = 1
	}

	for i := 0; i < max; i++ {
		encrypted, err := jwe.Encrypt(plaintext, jwa.A128KW, sharedkey, jwa.A128CBC_HS256, jwa.NoCompress)
		if !assert.NoError(t, err, "Encrypt is successful") {
			return
		}

		decrypted, err := jwe.Decrypt(encrypted, jwa.A128KW, sharedkey)
		if !assert.NoError(t, err, "Decrypt successful") {
			return
		}

		if !assert.Equal(t, plaintext, decrypted, "Decrypted correct plaintext") {
			return
		}
	}
}

func TestEncode_ECDHES(t *testing.T) {
	plaintext := []byte("Lorem ipsum")
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.NoError(t, err, "ecdsa key generated") {
		return
	}

	encrypted, err := jwe.Encrypt(plaintext, jwa.ECDH_ES_A128KW, &privkey.PublicKey, jwa.A128CBC_HS256, jwa.NoCompress)
	if !assert.NoError(t, err, "Encrypt succeeds") {
		return
	}

	msg, err := jwe.Parse(encrypted)
	if !assert.NoError(t, err, `jwe.Parse should succeed`) {
		t.Logf("%s", encrypted)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted, jwa.ECDH_ES_A128KW, privkey)
	if !assert.NoError(t, err, "Decrypt succeeds") {
		jsonbuf, _ := json.Marshal(msg)
		t.Logf("%s", jsonbuf)
		return
	}
	t.Logf("%s", decrypted)
}

func TestEncode_ECDH(t *testing.T) {
	plaintext := []byte("Lorem ipsum")
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.NoError(t, err, "ecdsa key generated") {
		return
	}

	algorithms := []jwa.KeyEncryptionAlgorithm{
		jwa.ECDH_ES_A256KW,
		jwa.ECDH_ES_A192KW,
		jwa.ECDH_ES_A128KW,
	}

	for _, alg := range algorithms {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			t.Parallel()

			encrypted, err := jwe.Encrypt(plaintext, alg, &privkey.PublicKey, jwa.A256GCM, jwa.NoCompress)
			if !assert.NoError(t, err, "Encrypt succeeds") {
				return
			}

			t.Logf("encrypted = %s", encrypted)

			msg, err := jwe.Parse(encrypted)
			if !assert.NoError(t, err, `jwe.Parse should succeed`) {
				return
			}

			t.Logf("%#v", msg)

			{
				buf, _ := json.MarshalIndent(msg, "", "  ")
				t.Logf("%s", buf)
			}
			{
				buf, _ := json.MarshalIndent(msg.ProtectedHeaders(), "", "  ")
				t.Logf("%s", buf)
			}

			decrypted, err := jwe.Decrypt(encrypted, alg, privkey)
			if !assert.NoError(t, err, "Decrypt succeeds") {
				return
			}
			t.Logf("%s", decrypted)
		})
	}
}

func Test_A256KW_A256CBC_HS512(t *testing.T) {
	var keysize = 32
	var key = make([]byte, keysize)
	for i := 0; i < keysize; i++ {
		key[i] = byte(i)
	}
	_, err := jwe.Encrypt([]byte(examplePayload), jwa.A256KW, key, jwa.A256CBC_HS512, jwa.NoCompress)
	if !assert.Error(t, err, "should fail to encrypt payload") {
		return
	}
}
