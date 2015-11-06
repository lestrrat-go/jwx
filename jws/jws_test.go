package jws

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/stretchr/testify/assert"
)

func TestRoundtrip_Compact(t *testing.T) {
	for _, alg := range []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512} {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if !assert.NoError(t, err, "RSA key generated") {
			return
		}

		signer, err := NewRsaSign(alg, key)
		if !assert.NoError(t, err, "RsaSign created") {
			return
		}
		hdr := NewHeader()
		hdr.Algorithm = alg
		hdr.KeyId = "foo"

		payload := buffer.Buffer("Hello, World!")
		buf, err := Encode(hdr, payload, signer)
		if !assert.NoError(t, err, "(%s) Encode is successful", alg) {
			return
		}

		c, err := ParseCompact(buf)
		if !assert.NoError(t, err, "ParseCompact is successful") {
			return
		}

		if !assert.Equal(t, buffer.Buffer("Hello, World!"), c.Payload, "Payload is decoded") {
			return
		}

		if !assert.NoError(t, c.Verify(signer), "Verify is successful") {
			return
		}
	}
}

func TestParse_CompactEncoded(t *testing.T) {
	// Appendix-A.4.1
	s := `eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn`

	m, err := Parse([]byte(s))
	if !assert.NoError(t, err, "Parsing compact serialization") {
		return
	}

	// TODO: verify m
	jsonbuf, _ := json.MarshalIndent(m, "", "  ")
	t.Logf("%s", jsonbuf)
}

func TestParse_UnsecuredCompact(t *testing.T) {
	s := `eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.`

	m, err := Parse([]byte(s))
	if !assert.NoError(t, err, "Parsing compact serialization") {
		return
	}

	{
		v := map[string]interface{}{}
		if !assert.NoError(t, json.Unmarshal(m.Payload.Bytes(), &v), "Unmarshal payload") {
			return
		}
		if !assert.Equal(t, v["iss"], "joe", "iss matches") {
			return
		}
		if !assert.Equal(t, int(v["exp"].(float64)), 1300819380, "exp matches") {
			return
		}
		if !assert.Equal(t, v["http://example.com/is_root"], true, "'http://example.com/is_root' matches") {
			return
		}
	}

	if !assert.Len(t, m.Signatures, 1, "There should be 1 signature") {
		return
	}

	sig := m.Signatures[0]
	if !assert.Equal(t, sig.Header.Algorithm, jwa.NoSignature, "Algorithm = 'none'") {
		return
	}
	if !assert.Empty(t, sig.Signature, "Signature should be empty") {
		return
	}
}

func TestParse_CompleteJSON(t *testing.T) {
	s := `{
    "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    "signatures":[
      {
        "header": {"kid":"2010-12-29"},
        "protected":"eyJhbGciOiJSUzI1NiJ9",
        "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
      },
      {
        "header": {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
        "protected":"eyJhbGciOiJFUzI1NiJ9",
        "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
      }
    ]
  }`

	m, err := Parse([]byte(s))
	if !assert.NoError(t, err, "Parsing complete json serialization") {
		return
	}

	if !assert.Len(t, m.Signatures, 2, "There should be 2 signatures") {
		return
	}

	jsonbuf, err := json.Marshal(m)
	if !assert.NoError(t, err, "Marshal JSON is successful") {
		return
	}

	b := &bytes.Buffer{}
	json.Compact(b, jsonbuf)

	if !assert.Equal(t, b.Bytes(), jsonbuf, "generated json matches") {
		return
	}
}

func TestParse_FlattenedJSON(t *testing.T) {
	s := `{
    "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    "protected":"eyJhbGciOiJFUzI1NiJ9",
    "header": {
      "kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"
    },
    "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
  }`

	m, err := Parse([]byte(s))
	if !assert.NoError(t, err, "Parsing flattened json serialization") {
		return
	}

	if !assert.Len(t, m.Signatures, 1, "There should be 1 signature") {
		return
	}

	jsonbuf, _ := json.MarshalIndent(m, "", "  ")
	t.Logf("%s", jsonbuf)
}
