package jwe_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	privkey, err := jwk.ParseKey(jwkstr)
	if err != nil {
		panic(err)
	}

	if err := jwk.Export(privkey, &rsaPrivKey); err != nil {
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

		buf, err := json.Marshal(msg)
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

	privkey, err := jwk.ParseKey(jwkstr)
	if !assert.NoError(t, err, `parsing jwk should succeed`) {
		return
	}

	var rawkey rsa.PrivateKey
	if !assert.NoError(t, jwk.Export(privkey, &rawkey), `obtaining raw key should succeed`) {
		return
	}

	msg := jwe.NewMessage()
	plaintext, err := jwe.Decrypt([]byte(serialized), jwe.WithKey(jwa.RSA_OAEP, rawkey), jwe.WithMessage(msg))
	if !assert.NoError(t, err, "jwe.Decrypt should be successful") {
		return
	}

	if !assert.Equal(t, 1, len(msg.Recipients()), "message recipients header length is 1") {
		return
	}

	if !assert.Equal(t, payload, string(plaintext), "decrypted value does not match") {
		return
	}

	templates := []*struct {
		Name     string
		Options  []jwe.EncryptOption
		Expected string
	}{
		{
			Name:     "Compact",
			Options:  []jwe.EncryptOption{jwe.WithCompact()},
			Expected: serialized,
		},
		{
			Name:     "JSON",
			Options:  []jwe.EncryptOption{jwe.WithJSON()},
			Expected: `{"ciphertext":"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A","iv":"48V1_ALb6US04U3b","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","header":{"alg":"RSA-OAEP"},"encrypted_key":"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg","tag":"XFBoMYUZodetZdvTiFvSkQ"}`,
		},
		{
			Name:    "JSON (Pretty)",
			Options: []jwe.EncryptOption{jwe.WithJSON(jwe.WithPretty(true))},
			Expected: `{
  "ciphertext": "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A",
  "iv": "48V1_ALb6US04U3b",
  "protected": "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ",
  "header": {
    "alg": "RSA-OAEP"
  },
  "encrypted_key": "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg",
  "tag": "XFBoMYUZodetZdvTiFvSkQ"
}`,
		},
	}

	ntmpl := len(templates)
	testcases := make([]struct {
		Name     string
		Options  []jwe.EncryptOption
		Expected string
	}, ntmpl*2)

	for i, tmpl := range templates {
		options := make([]jwe.EncryptOption, len(tmpl.Options))
		copy(options, tmpl.Options)

		for j, compression := range []jwa.CompressionAlgorithm{jwa.NoCompress, jwa.Deflate} {
			compName := compression.String()
			if compName == "" {
				compName = "none"
			}
			tc := testcases[i+j]
			tc.Name = tmpl.Name + " (compression=" + compName + ")"
			tc.Expected = tmpl.Expected
			tc.Options = append(options, jwe.WithCompress(compression))
		}
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			options := tc.Options
			options = append(options, jwe.WithKey(jwa.RSA_OAEP, rawkey.PublicKey))

			encrypted, err := jwe.Encrypt(plaintext, options...)
			if !assert.NoError(t, err, "jwe.Encrypt should succeed") {
				return
			}
			t.Logf("%s", encrypted)

			t.Run("WithKey", func(t *testing.T) {
				plaintext, err = jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, rawkey))
				if !assert.NoError(t, err, "jwe.Decrypt should succeed") {
					return
				}

				if !assert.Equal(t, payload, string(plaintext), "jwe.Decrypt should produce the same plaintext") {
					return
				}
			})
			t.Run("WithKeySet", func(t *testing.T) {
				pkJwk, err := jwk.FromRaw(rawkey)
				if !assert.NoError(t, err, `jwk.New should succeed`) {
					return
				}
				// Keys are not going to be selected without an algorithm
				_ = pkJwk.Set(jwe.AlgorithmKey, jwa.RSA_OAEP)
				set := jwk.NewSet()
				set.AddKey(pkJwk)

				var used interface{}
				plaintext, err = jwe.Decrypt(encrypted, jwe.WithKeySet(set, jwe.WithRequireKid(false)), jwe.WithKeyUsed(&used))
				if !assert.NoError(t, err, "jwe.Decrypt should succeed") {
					return
				}

				if !assert.Equal(t, payload, string(plaintext), "jwe.Decrypt should produce the same plaintext") {
					return
				}

				if !assert.Equal(t, pkJwk, used) {
					return
				}
			})
		})
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

	iterations := 100
	if testing.Short() {
		iterations = 1
	}

	for range iterations {
		encrypted, err := jwe.Encrypt(plaintext, jwe.WithKey(jwa.RSA_OAEP, &rsaPrivKey.PublicKey))
		if !assert.NoError(t, err, "Encrypt should succeed") {
			return
		}

		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, rsaPrivKey))
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

	iterations := 100
	if testing.Short() {
		iterations = 1
	}

	for range iterations {
		encrypted, err := jwe.Encrypt(plaintext, jwe.WithKey(jwa.RSA1_5, &rsaPrivKey.PublicKey), jwe.WithContentEncryption(jwa.A128CBC_HS256))
		if !assert.NoError(t, err, "Encrypt is successful") {
			return
		}

		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA1_5, rsaPrivKey))
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

	iterations := 100
	if testing.Short() {
		iterations = 1
	}

	for range iterations {
		encrypted, err := jwe.Encrypt(plaintext, jwe.WithKey(jwa.A128KW, sharedkey), jwe.WithContentEncryption(jwa.A128CBC_HS256))
		if !assert.NoError(t, err, "Encrypt is successful") {
			return
		}

		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW, sharedkey))
		if !assert.NoError(t, err, "Decrypt successful") {
			return
		}

		if !assert.Equal(t, plaintext, decrypted, "Decrypted correct plaintext") {
			return
		}
	}
}

//nolint:thelper
func testEncodeECDHWithKey(t *testing.T, privkey interface{}, pubkey interface{}) {
	plaintext := []byte("Lorem ipsum")

	algorithms := []jwa.KeyEncryptionAlgorithm{
		jwa.ECDH_ES,
		jwa.ECDH_ES_A256KW,
		jwa.ECDH_ES_A192KW,
		jwa.ECDH_ES_A128KW,
	}

	for _, alg := range algorithms {
		t.Run(alg.String(), func(t *testing.T) {
			encrypted, err := jwe.Encrypt(plaintext, jwe.WithKey(alg, pubkey))
			if !assert.NoError(t, err, "Encrypt succeeds") {
				return
			}

			_, err = jwe.Parse(encrypted)
			if !assert.NoError(t, err, `jwe.Parse should succeed`) {
				return
			}

			decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(alg, privkey))
			if !assert.NoError(t, err, "Decrypt succeeds") {
				return
			}
			t.Logf("%s", decrypted)
		})
	}
}

func TestEncode_ECDH(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}
	for _, crv := range curves {
		t.Run(crv.Params().Name, func(t *testing.T) {
			privkey, err := ecdsa.GenerateKey(crv, rand.Reader)
			if !assert.NoError(t, err, `ecdsa.GenerateKey should succeed`) {
				return
			}

			testEncodeECDHWithKey(t, privkey, &privkey.PublicKey)
		})
	}
}

func TestEncode_X25519(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err, `ecdh.X25519().GenerateKey should succeed`)

	testEncodeECDHWithKey(t, priv, priv.Public())
}

func Test_GHIssue207(t *testing.T) {
	const plaintext = "hi\n"
	var testcases = []struct {
		Algorithm  jwa.KeyEncryptionAlgorithm
		Key        string
		Data       string
		Thumbprint string
		Name       string
	}{
		{
			Name:       `ECDH-ES`,
			Key:        `{"alg":"ECDH-ES","crv":"P-521","d":"ARxUkIjnB7pjFzM2OIIFcclR-4qbZwv7DoC96cksPKyvVWOkEsZ0CK6deM4AC6G5GClR5TXWMQVC_bNDmfuwPPqF","key_ops":["wrapKey","unwrapKey"],"kty":"EC","x":"ACewmG5j0POUDQw3rIqFQozK_6yXUsfNjiZtWqQOU7MXsSKK9RsRS8ySmeTG14heUpbbnrC9VdYKSOUGkYnYUl2Y","y":"ACkXSOma_FP93R3u5uYX7gUOlM0LDkNsij9dVFPbafF8hlfYEnUGit2o-tt7W0Zq3t38jEhpjUoGgM04JDJ6_m0x"}`,
			Data:       `{"ciphertext":"sp0cLt4Rx1p0Ax0Q1OZj7w","header":{"alg":"ECDH-ES","epk":{"crv":"P-521","kty":"EC","x":"APMKQpje5vu39-eS_LX_g15stqbNZ37GgYimW8PZf7d_OOuAygK2YlINYnPoUybrxkoaLRPhbmxc9MBWFdaY8SXx","y":"AMpq4DFi6w-pfnprO58CkfX-ncXtJ8fvox2Ej8Ey3ZY1xjVUtbDJCDCjY53snYaNCEjnFQPAn-IkAG90p2Xcm8ut"}},"iv":"Fjnb5uUWp9euqp1MK_hT4A","protected":"eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","tag":"6nhiy-vyqwVjpy08jrorTpWqvam66HdKxU36XsE3Z3s"}`,
			Thumbprint: `0_6x6e2sZKeq3ka0QV0PEkJagqg`,
		},
		{
			Name:       `ECDH-ES+A256KW`,
			Key:        `{"alg":"ECDH-ES+A256KW","crv":"P-521","d":"AcH8h_ctsMnopTiCH7wiuM-nAb1CNikC0ubcOZQDLYSVEw93h6_D57aD7DLWbjIsVNzn7Qq8P-kRiTYVoH5GTQVg","key_ops":["wrapKey","unwrapKey"],"kty":"EC","x":"AAQoEbNeiG3ExYj9bJLGFn4h_bFjERfIcmpQMW5KWlFhqcXTFg0g8-5YWjdJXdNmO_2EuaKe7zOvEq8dCFCb12-R","y":"Ad8E2jp6FSCSd8laERqIt67A2T-MIqQE5301jNYb5SMsCSV1rs1McyvhzHaclYcqTUptoA-rW5kNS9N5124XPHky"}`,
			Data:       `{"ciphertext":"evXmzoQ5TWQvEXdpv9ZCBQ","encrypted_key":"ceVsjF-0LhziK75oHRC-C539hlFJMSbub015a3YtIBgCt7c0IRzkzwoOvo_Jf44FXZi0Vd-4fvDjRkZDzx9DcuDd4ASYDLvW","header":{"alg":"ECDH-ES+A256KW","epk":{"crv":"P-521","kty":"EC","x":"Aad7PFl9cct7WcfM3b_LNkhCHfCotW_nRuarX7GACDyyZkr2dd1g6r3rz-8r2-AyOGD9gc2nhrTEjVHT2W7eu65U","y":"Ab0Mj6BK8g3Fok6oyFlkvKOyquEVxeeJOlsyXKYBputPxFT5Gljr2FoJdViAxVspoSiw1K5oG1h59UBJgPWG4GQV"}},"iv":"KsJgq2xyzE1dZi2BM2xf5g","protected":"eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","tag":"b6m_nW9vfk6xJugm_-Uuj4cbAQh9ECelLc1ZBfO86L0"}`,
			Thumbprint: `G4OtKQL_qr9Q57atNOU6SJnJxB8`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			webKey, err := jwk.ParseKey([]byte(tc.Key))
			if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
				return
			}

			thumbprint, err := webKey.Thumbprint(crypto.SHA1)
			if !assert.NoError(t, err, `jwk.Thumbprint should succeed`) {
				return
			}

			if !assert.Equal(t, base64.RawURLEncoding.EncodeToString(thumbprint), tc.Thumbprint, `thumbprints should match`) {
				return
			}

			var key ecdsa.PrivateKey
			if !assert.NoError(t, jwk.Export(webKey, &key), `jwk.Export should succeed`) {
				return
			}

			decrypted, err := jwe.Decrypt([]byte(tc.Data), jwe.WithKeyProvider(jwe.KeyProviderFunc(func(_ context.Context, sink jwe.KeySink, r jwe.Recipient, _ *jwe.Message) error {
				sink.Key(r.Headers().Algorithm(), &key)
				return nil
			})))
			if !assert.NoError(t, err, `jwe.Decrypt should succeed`) {
				return
			}

			if !assert.Equal(t, string(decrypted), plaintext, `plaintext should match`) {
				return
			}
		})
	}
}

// tests direct key encryption by encrypting-decrypting a plaintext
func TestEncode_Direct(t *testing.T) {
	var testcases = []struct {
		Algorithm jwa.ContentEncryptionAlgorithm
		KeySize   int // in bytes
	}{
		{jwa.A128CBC_HS256, 32},
		{jwa.A128GCM, 16},
		{jwa.A192CBC_HS384, 48},
		{jwa.A192GCM, 24},
		{jwa.A256CBC_HS512, 64},
		{jwa.A256GCM, 32},
	}
	plaintext := []byte("Lorem ipsum")

	for _, tc := range testcases {
		t.Run(tc.Algorithm.String(), func(t *testing.T) {
			key := make([]byte, tc.KeySize)
			/*
				_, err := rand.Read(key)
				if !assert.NoError(t, err, "Key generation succeeds") {
					return
				}*/
			for n := 0; n < len(key); {
				w := copy(key[n:], []byte(`12345678`))
				n += w
			}

			encrypted, err := jwe.Encrypt(plaintext, jwe.WithKey(jwa.DIRECT, key), jwe.WithContentEncryption(tc.Algorithm))
			if !assert.NoError(t, err, `jwe.Encrypt should succeed`) {
				return
			}
			decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.DIRECT, key))
			if !assert.NoError(t, err, `jwe.Decrypt should succeed`) {
				return
			}

			assert.Equal(t, plaintext, decrypted, `jwe.Decrypt should match input plaintext`)
		})
	}
}

// Decrypts messages generated by `jose` tool. It helps check compatibility with other jwx implementations.
func TestDecodePredefined_Direct(t *testing.T) {
	var testcases = []struct {
		Algorithm  jwa.ContentEncryptionAlgorithm
		Key        string // generated with 'jose jwk gen -i '{"alg":"A128GCM"}' -o key.jwk'
		Thumbprint string // generated with 'jose jwk thp -i key.jwk`
		Data       string // generated with 'jose jwe enc -I msg.txt -k key.jwk -o msg.jwe'
	}{
		{
			jwa.A128CBC_HS256,
			`{"alg":"A128GCM","k":"9hexZKVSV9pZhPNzgXiD8g","key_ops":["encrypt","decrypt"],"kty":"oct"}`,
			`RwW22IemrIJLFwlqZ-OQUe_Lnbo`,
			`{"ciphertext":"FX_px9cuyO_hZfo","encrypted_key":"","header":{"alg":"dir"},"iv":"Z9CRJCFPtpEI5Pwq","protected":"eyJlbmMiOiJBMTI4R0NNIn0","tag":"1iq0MNDX40XVtqGYinhUtQ"}`,
		},
		{
			jwa.A128GCM,
			`{"alg":"A128GCM","k":"9hexZKVSV9pZhPNzgXiD8g","key_ops":["encrypt","decrypt"],"kty":"oct"}`,
			`RwW22IemrIJLFwlqZ-OQUe_Lnbo`,
			`{"ciphertext":"FX_px9cuyO_hZfo","encrypted_key":"","header":{"alg":"dir"},"iv":"Z9CRJCFPtpEI5Pwq","protected":"eyJlbmMiOiJBMTI4R0NNIn0","tag":"1iq0MNDX40XVtqGYinhUtQ"}`,
		},
		{
			jwa.A192CBC_HS384,
			`{"alg":"A128GCM","k":"9hexZKVSV9pZhPNzgXiD8g","key_ops":["encrypt","decrypt"],"kty":"oct"}`,
			`RwW22IemrIJLFwlqZ-OQUe_Lnbo`,
			`{"ciphertext":"FX_px9cuyO_hZfo","encrypted_key":"","header":{"alg":"dir"},"iv":"Z9CRJCFPtpEI5Pwq","protected":"eyJlbmMiOiJBMTI4R0NNIn0","tag":"1iq0MNDX40XVtqGYinhUtQ"}`,
		},
		{
			jwa.A192GCM,
			`{"alg":"A128GCM","k":"9hexZKVSV9pZhPNzgXiD8g","key_ops":["encrypt","decrypt"],"kty":"oct"}`,
			`RwW22IemrIJLFwlqZ-OQUe_Lnbo`,
			`{"ciphertext":"FX_px9cuyO_hZfo","encrypted_key":"","header":{"alg":"dir"},"iv":"Z9CRJCFPtpEI5Pwq","protected":"eyJlbmMiOiJBMTI4R0NNIn0","tag":"1iq0MNDX40XVtqGYinhUtQ"}`,
		},
		{
			jwa.A256CBC_HS512,
			`{"alg":"A128GCM","k":"9hexZKVSV9pZhPNzgXiD8g","key_ops":["encrypt","decrypt"],"kty":"oct"}`,
			`RwW22IemrIJLFwlqZ-OQUe_Lnbo`,
			`{"ciphertext":"FX_px9cuyO_hZfo","encrypted_key":"","header":{"alg":"dir"},"iv":"Z9CRJCFPtpEI5Pwq","protected":"eyJlbmMiOiJBMTI4R0NNIn0","tag":"1iq0MNDX40XVtqGYinhUtQ"}`,
		},
		{
			jwa.A256GCM,
			`{"alg":"A128GCM","k":"9hexZKVSV9pZhPNzgXiD8g","key_ops":["encrypt","decrypt"],"kty":"oct"}`,
			`RwW22IemrIJLFwlqZ-OQUe_Lnbo`,
			`{"ciphertext":"FX_px9cuyO_hZfo","encrypted_key":"","header":{"alg":"dir"},"iv":"Z9CRJCFPtpEI5Pwq","protected":"eyJlbmMiOiJBMTI4R0NNIn0","tag":"1iq0MNDX40XVtqGYinhUtQ"}`,
		},
	}
	plaintext := "Lorem ipsum"

	for _, tc := range testcases {
		t.Run(tc.Algorithm.String(), func(t *testing.T) {
			webKey, err := jwk.ParseKey([]byte(tc.Key))
			if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
				return
			}

			thumbprint, err := webKey.Thumbprint(crypto.SHA1)
			if !assert.NoError(t, err, `jwk.Thumbprint should succeed`) {
				return
			}

			if !assert.Equal(t, base64.RawURLEncoding.EncodeToString(thumbprint), tc.Thumbprint, `thumbprints should match`) {
				return
			}

			var key []byte
			if !assert.NoError(t, jwk.Export(webKey, &key), `jwk.Export should succeed`) {
				return
			}

			decrypted, err := jwe.Decrypt([]byte(tc.Data), jwe.WithKey(jwa.DIRECT, key))
			if !assert.NoError(t, err, `jwe.Decrypt should succeed`) {
				return
			}

			if !assert.Equal(t, plaintext, string(decrypted), `plaintext should match`) {
				return
			}
		})
	}
}

func TestGHIssue230(t *testing.T) {
	t.Parallel()

	const data = `{"ciphertext":"wko","encrypted_key":"","iv":"y-wj7nfa-T8XG58z","protected":"eyJhbGciOiJkaXIiLCJjbGV2aXMiOnsicGluIjoidHBtMiIsInRwbTIiOnsiaGFzaCI6InNoYTI1NiIsImp3a19wcml2IjoiQU80QUlCSTFRYjQ2SHZXUmNSRHVxRXdoN2ZWc3hSNE91MVhsOHBRX2hMMTlPeUc3QUJDVG80S2RqWEZYcEFUOWtLeWptVVJPOTVBaXc4U1o4MGZXRmtDMGdEazJLTXEtamJTZU1wcFZFaFJaWEpxQmhWNXVGZ1V0T0J4eUFjRzFZRjhFMW5Ob1dPWk9Eek5EUkRrOE1ZVWZrWVNpS0ZKb2pPZ0UxSjRIZkRoM0lBelY2MFR6V2NWcXJ0QnlwX2EyZ1V2a0JqcGpTeVF2Nmc2amJMSXpEaG10VnZLMmxDazhlMjUzdG1MSDNPQWk0Q0tZcWFZY0tjTTltSTdTRXBpVldlSjZZVFBEdmtORndpa0tNRjE3czVYQUlFUjZpczNNTVBpNkZTOWQ3ZmdMV25hUkpabDVNNUJDMldxN2NsVmYiLCJqd2tfcHViIjoiQUM0QUNBQUxBQUFFMGdBQUFCQUFJREpTSVhRSVVocjVPaDVkNXZWaWVGUDBmZG9pVFd3S1RicXJRRVRhVmx4QyIsImtleSI6ImVjYyJ9fSwiZW5jIjoiQTI1NkdDTSJ9","tag":"lir7v9YbCCZQKf5-yJ0BTQ"}`

	msg, err := jwe.Parse([]byte(data))
	if !assert.NoError(t, err, `jwe.Parse should succeed`) {
		return
	}

	compact, err := jwe.Compact(msg)
	if !assert.NoError(t, err, `jwe.Compact should succeed`) {
		return
	}

	msg2, err := jwe.Parse(compact)
	if !assert.NoError(t, err, `jwe.Parse should succeed`) {
		return
	}

	if !assert.Equal(t, msg, msg2, `data -> msg -> compact -> msg2 produces msg == msg2`) {
		t.Logf("msg -> %#v", msg)
		t.Logf("msg2 -> %#v", msg2)
		return
	}
}

func TestReadFile(t *testing.T) {
	const s = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ`

	f, err := os.CreateTemp("", "test-read-file-*.jwe")
	if !assert.NoError(t, err, `os.CreateTemp should succeed`) {
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "%s", s)

	if _, err := jwe.ReadFile(f.Name()); !assert.NoError(t, err, `jwe.ReadFile should succeed`) {
		return
	}
}

func TestCustomField(t *testing.T) {
	// XXX has global effect!!!
	const rfc3339Key = `x-test-rfc3339`
	const rfc1123Key = `x-test-rfc1123`
	jwe.RegisterCustomField(rfc3339Key, time.Time{})
	jwe.RegisterCustomField(rfc1123Key, jwe.CustomDecodeFunc(func(data []byte) (interface{}, error) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		return time.Parse(time.RFC1123, s)
	}))

	defer jwe.RegisterCustomField(rfc3339Key, nil)
	defer jwe.RegisterCustomField(rfc1123Key, nil)

	expected := time.Date(2015, 11, 4, 5, 12, 52, 0, time.UTC)
	rfc3339bytes, _ := expected.MarshalText() // RFC3339
	rfc1123bytes := expected.Format(time.RFC1123)

	plaintext := []byte("Hello, World!")
	rsakey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk() should succeed`)

	pubkey, err := jwk.PublicKeyOf(rsakey)
	require.NoError(t, err, `jwk.PublicKeyOf() should succeed`)

	t.Run("jwe.Parse", func(t *testing.T) {
		protected := jwe.NewHeaders()
		protected.Set(rfc3339Key, string(rfc3339bytes))
		protected.Set(rfc1123Key, rfc1123bytes)

		encrypted, err := jwe.Encrypt(plaintext, jwe.WithKey(jwa.RSA_OAEP, pubkey), jwe.WithProtectedHeaders(protected))
		require.NoError(t, err, `jwe.Encrypt should succeed`)
		msg, err := jwe.Parse(encrypted)
		if !assert.NoError(t, err, `jwe.Parse should succeed`) {
			t.Logf("%q", encrypted)
			return
		}

		for _, key := range []string{rfc3339Key, rfc1123Key} {
			var v time.Time
			require.NoError(t, msg.ProtectedHeaders().Get(key, &v), `msg.Get(%q) should succeed`, key)
			require.Equal(t, expected, v, `values should match`)
		}
	})
	t.Run("json.Unmarshal", func(t *testing.T) {
		protected := jwe.NewHeaders()
		protected.Set(rfc3339Key, string(rfc3339bytes))
		protected.Set(rfc1123Key, rfc1123bytes)

		encrypted, err := jwe.Encrypt(plaintext, jwe.WithKey(jwa.RSA_OAEP, pubkey), jwe.WithProtectedHeaders(protected), jwe.WithJSON())
		require.NoError(t, err, `jwe.Encrypt should succeed`)
		msg := jwe.NewMessage()
		if !assert.NoError(t, json.Unmarshal(encrypted, msg), `json.Unmarshal should succeed`) {
			return
		}

		for _, key := range []string{rfc3339Key, rfc1123Key} {
			var v time.Time
			require.NoError(t, msg.ProtectedHeaders().Get(key, &v), `msg.Get(%q) should succeed`, key)
			require.Equal(t, expected, v, `values should match`)
		}
	})
}

func TestGH554(t *testing.T) {
	const keyID = `very-secret-key`
	const plaintext = `hello world!`
	privkey, err := jwxtest.GenerateEcdsaJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateEcdsaJwk() should succeed`) {
		return
	}

	_ = privkey.Set(jwk.KeyIDKey, keyID)

	pubkey, err := jwk.PublicKeyOf(privkey)
	if !assert.NoError(t, err, `jwk.PublicKeyOf() should succeed`) {
		return
	}

	if !assert.Equal(t, keyID, pubkey.KeyID(), `key ID should match`) {
		return
	}

	encrypted, err := jwe.Encrypt([]byte(plaintext), jwe.WithKey(jwa.ECDH_ES, pubkey))
	if !assert.NoError(t, err, `jwk.Encrypt() should succeed`) {
		return
	}

	msg, err := jwe.Parse(encrypted)
	if !assert.NoError(t, err, `jwe.Parse() should succeed`) {
		return
	}

	recipients := msg.Recipients()

	// The epk must have the same key ID as the original
	kid := recipients[0].Headers().KeyID()
	if !assert.Equal(t, keyID, kid, `key ID in epk should match`) {
		return
	}
}

func TestGH803(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err, `ecdsa.GenerateKey should succeed`)

	payload := []byte("Lorem Ipsum")
	apu := []byte(`Alice`)
	apv := []byte(`Bob`)
	hdrs := jwe.NewHeaders()
	hdrs.Set(jwe.AgreementPartyUInfoKey, apu)
	hdrs.Set(jwe.AgreementPartyVInfoKey, apv)
	encrypted, err := jwe.Encrypt(
		payload,
		jwe.WithJSON(),
		jwe.WithKey(jwa.ECDH_ES, privateKey.PublicKey, jwe.WithPerRecipientHeaders(hdrs)),
		jwe.WithContentEncryption(jwa.A128GCM),
	)
	require.NoError(t, err, `jwe.Encrypt should succeed`)

	var msg jwe.Message
	decrypted, err := jwe.Decrypt(
		encrypted,
		jwe.WithKey(jwa.ECDH_ES, privateKey),
		jwe.WithMessage(&msg),
	)
	require.NoError(t, err, `jwe.Decrypt should succeed`)
	require.Equal(t, payload, decrypted, `decrypt messages match`)
	require.Equal(t, apu, msg.ProtectedHeaders().AgreementPartyUInfo())
	require.Equal(t, apv, msg.ProtectedHeaders().AgreementPartyVInfo())
}

func TestGH840(t *testing.T) {
	// Go 1.19+ panics if elliptic curve operations are called against
	// a point that's _NOT_ on the curve
	untrustedJWK := []byte(`{
		"kty": "EC",
		"crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqx7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	}`)

	privkey, err := jwk.ParseKey(untrustedJWK)
	require.NoError(t, err, `jwk.ParseKey should succeed`)

	pubkey, err := privkey.PublicKey()
	require.NoError(t, err, `privkey.PublicKey should succeed`)

	const payload = `Lorem ipsum`
	_, err = jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.ECDH_ES_A128KW, pubkey))
	require.Error(t, err, `jwe.Encrypt should fail (instead of panic)`)
}

type dummyKeyEncrypterDecrypter struct {
	key []byte
}

func (kd *dummyKeyEncrypterDecrypter) DecryptKey(_ jwa.KeyEncryptionAlgorithm, cek []byte, _ jwe.Recipient, _ *jwe.Message) ([]byte, error) {
	return bytes.TrimSuffix(cek, kd.key), nil
}

func (kd *dummyKeyEncrypterDecrypter) Algorithm() jwa.KeyEncryptionAlgorithm {
	return jwa.A128GCMKW
}

func (kd *dummyKeyEncrypterDecrypter) EncryptKey(key []byte) ([]byte, error) {
	return append(key, kd.key...), nil
}

var _ jwe.KeyEncrypter = (*dummyKeyEncrypterDecrypter)(nil)

func TestGH924(t *testing.T) {
	sharedKey := []byte("abra-kadabra")

	ked := &dummyKeyEncrypterDecrypter{key: sharedKey}

	payload := []byte("Lorem Ipsum")
	encrypted, err := jwe.Encrypt(
		payload,
		jwe.WithJSON(),
		jwe.WithKey(jwa.A128GCMKW, ked),
		jwe.WithContentEncryption(jwa.A128GCM),
	)
	require.NoError(t, err, `jwe.Encrypt should succeed`)

	var msg jwe.Message
	decrypted, err := jwe.Decrypt(
		encrypted,
		jwe.WithKey(jwa.A128GCMKW, ked),
		jwe.WithMessage(&msg),
	)
	require.NoError(t, err, `jwe.Decrypt should succeed`)
	require.Equal(t, payload, decrypted, `decrypt messages match`)
}

func TestGH1001(t *testing.T) {
	rawKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)

	encrypted, err := jwe.Encrypt([]byte("Lorem Ipsum"), jwe.WithKey(jwa.RSA_OAEP, rawKey.PublicKey))
	require.NoError(t, err, `jwe.Encrypt should succeed`)
	var cek []byte
	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, rawKey), jwe.WithCEK(&cek))
	require.NoError(t, err, `jwe.Decrypt should succeed`)

	require.Equal(t, "Lorem Ipsum", string(decrypted), `decrypted message should match`)
	require.NotNil(t, cek, `cek should not be nil`)

	reEncrypted, err := jwe.EncryptStatic([]byte("Lorem Ipsum"), cek, jwe.WithKey(jwa.RSA_OAEP, rawKey.PublicKey))
	require.NoError(t, err, `jwe.EncryptStatic should succeed`)

	// sanity. empty CEKs should be rejected
	_, err = jwe.EncryptStatic([]byte("Lorem Ipsum"), nil, jwe.WithKey(jwa.RSA_OAEP, rawKey.PublicKey))
	require.Error(t, err, `jwe.Encryptstatic should fail with empty cek`)

	cek = []byte(nil)
	decrypted, err = jwe.Decrypt(reEncrypted, jwe.WithKey(jwa.RSA_OAEP, rawKey), jwe.WithCEK(&cek))
	require.NoError(t, err, `jwe.Decrypt should succeed`)

	require.Equal(t, "Lorem Ipsum", string(decrypted), `decrypted message should match`)
	require.NotNil(t, cek, `cek should not be nil`)
}

func TestGHSA_7f9x_gw85_8grf(t *testing.T) {
	token := []byte("eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjoyMDAwMDAwMDAwLCJwMnMiOiJNNzczSnlmV2xlX2FsSXNrc0NOTU9BIn0=.S8B1kXdIR7BM6i_TaGsgqEOxU-1Sgdakp4mHq7UVhn-_REzOiGz2gg.gU_LfzhBXtQdwYjh.9QUIS-RWkLc.m9TudmzUoCzDhHsGGfzmCA")
	key, err := jwk.FromRaw([]byte(`abcdefg`))
	require.NoError(t, err, `jwk.FromRaw should succeed`)

	{
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		done := make(chan struct{})
		go func(t *testing.T, done chan struct{}) {
			_, err := jwe.Decrypt(token, jwe.WithKey(jwa.PBES2_HS256_A128KW, key))
			require.Error(t, err, `jwe.Decrypt should fail`)
			close(done)
		}(t, done)

		select {
		case <-done:
		case <-ctx.Done():
			require.Fail(t, "jwe.Decrypt should not block")
		}
	}

	// NOTE: HAS GLOBAL EFFECT
	// Should allow for timeout to occur
	jwe.Settings(jwe.WithMaxPBES2Count(100000000000000000))

	// put it back to normal after the test
	defer jwe.Settings(jwe.WithMaxPBES2Count(10000))
	{
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		done := make(chan struct{})
		go func(done chan struct{}) {
			_, _ = jwe.Decrypt(token, jwe.WithKey(jwa.PBES2_HS256_A128KW, key))
			close(done)
		}(done)

		select {
		case <-done:
			require.Fail(t, "jwe.Decrypt should block")
		case <-ctx.Done():
			// timeout occurred as it should
		}
	}
}

func TestMaxBufferSize(t *testing.T) {
	// NOTE: This has GLOBAL EFFECT
	jwe.Settings(jwe.WithMaxBufferSize(1))
	defer jwe.Settings(jwe.WithMaxBufferSize(0))

	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	_, err = jwe.Encrypt([]byte("Lorem Ipsum"), jwe.WithContentEncryption(jwa.A128CBC_HS256), jwe.WithKey(jwa.RSA_OAEP, key))
	require.Error(t, err, `jwe.Encrypt should fail`)
}

func TestMaxDecompressBufferSize(t *testing.T) {
	// This payload size is intentionally set to a small value to avoid
	// causing problems for regular users and CI/CD systems. If you wish to
	// verify that root issue is fixed, you may want to try increasing the
	// payload size to a larger value.
	const payloadSize = 1 << 16

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, `rsa.GenerateKey should succeed`)

	pubkey := &privkey.PublicKey

	wrongPrivkey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, `rsa.GenerateKey should succeed`)
	wrongPubkey := &wrongPrivkey.PublicKey

	payload := strings.Repeat("x", payloadSize)

	testcases := []struct {
		Name                  string
		GlobalMaxSize         int64
		PublicKey             *rsa.PublicKey
		Error                 bool
		ProcessDecryptOptions func([]jwe.DecryptOption) []jwe.DecryptOption
	}{
		// This should work, because we set the MaxSize to be large (==payload size)
		{
			Name:          "same as payload size",
			GlobalMaxSize: payloadSize,
			PublicKey:     pubkey,
		},
		// This should fail, because we set the GlobalMaxSize to be smaller than the payload size
		{
			Name:          "smaller than payload size",
			GlobalMaxSize: payloadSize - 1,
			PublicKey:     pubkey,
			Error:         true,
		},
		// This should fail, because the public key does not match the
		// private key used to decrypt the payload. In essence this way
		// we do NOT trigger the root cause of this issue, but we bail out early
		{
			Name:          "Wrong PublicKey",
			GlobalMaxSize: payloadSize,
			PublicKey:     wrongPubkey,
			Error:         true,
		},
		{
			Name:          "global=payloadSize-1, per-call=payloadSize",
			GlobalMaxSize: payloadSize - 1,
			PublicKey:     pubkey,
			ProcessDecryptOptions: func(options []jwe.DecryptOption) []jwe.DecryptOption {
				return append(options, jwe.WithMaxDecompressBufferSize(payloadSize))
			},
		},
		// This should be the last test case to put the value back to default :)
		{
			Name:          "Default 10MB globally",
			GlobalMaxSize: 10 * 1024 * 1024,
			PublicKey:     pubkey,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			jwe.Settings(jwe.WithMaxDecompressBufferSize(tc.GlobalMaxSize))

			encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP, tc.PublicKey), jwe.WithContentEncryption("A128CBC-HS256"), jwe.WithCompress(jwa.Deflate))

			require.NoError(t, err, `jwe.Encrypt should succeed`)

			decryptOptions := []jwe.DecryptOption{jwe.WithKey(jwa.RSA_OAEP, privkey)}

			if fn := tc.ProcessDecryptOptions; fn != nil {
				decryptOptions = fn(decryptOptions)
			}
			_, err = jwe.Decrypt(encrypted, decryptOptions...)
			if tc.Error {
				require.Error(t, err, `jwe.Decrypt should fail`)
			} else {
				require.NoError(t, err, `jwe.Decrypt should succeed`)
			}
		})
	}
}
