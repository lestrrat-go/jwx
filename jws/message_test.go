package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

func TestMessage(t *testing.T) {
	t.Run("JSON", func(t *testing.T) {
		const src = `{
  "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  "signatures": [
    {
      "header": {
        "kid": "2010-12-29"
      },
      "protected": "eyJhbGciOiJSUzI1NiJ9",
      "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
    },
    {
      "header": {
        "kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"
      },
      "protected": "eyJhbGciOiJFUzI1NiJ9",
      "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
    }
  ]
}`

		var m jws.Message
		require.NoError(t, json.Unmarshal([]byte(src), &m), `json.Unmarshal should succeed`)

		buf, err := json.MarshalIndent(m, "", "  ")
		require.NoError(t, err, `json.Marshal should succeed`)
		require.Equal(t, src, string(buf), `roundtrip should match`)
	})
	t.Run("Construction/Manipulation", func(t *testing.T) {
		const payload = `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`
		const encodedSig1 = `cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw`
		const encodedSig2 = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

		decodedPayload, err := base64.DecodeString(payload)
		require.NoError(t, err, `base64.DecodeString should succeed (payload)`)

		decodedSig1, err := base64.DecodeString(encodedSig1)
		require.NoError(t, err, `base64.DecodeString should succeed (sig1)`)

		decodedSig2, err := base64.DecodeString(encodedSig2)
		require.NoError(t, err, `base64.DecodeString should succeed (sig2)`)

		public1 := jws.NewHeaders()
		require.NoError(t, public1.Set(jws.AlgorithmKey, jwa.RS256()), `public1.Set should succeed`)
		protected1 := jws.NewHeaders()
		require.NoError(t, protected1.Set(jws.KeyIDKey, "2010-12-29"), `protected1.Set should succeed`)

		public2 := jws.NewHeaders()
		require.NoError(t, public2.Set(jws.AlgorithmKey, jwa.ES256()), `public2.Set should succeed`)
		protected2 := jws.NewHeaders()
		require.NoError(t, protected2.Set(jws.KeyIDKey, "e9bc097a-ce51-4036-9562-d2ade882db0d"), `protected2.Set should succeed`)

		m := jws.NewMessage().
			SetPayload(decodedPayload).
			AppendSignature(
				jws.NewSignature().
					SetSignature(decodedSig1).
					SetProtectedHeaders(public1).
					SetPublicHeaders(protected1),
			).
			AppendSignature(
				jws.NewSignature().
					SetSignature(decodedSig2).
					SetProtectedHeaders(public2).
					SetPublicHeaders(protected2),
			)

		const expected = `{
  "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  "signatures": [
    {
      "header": {
        "kid": "2010-12-29"
      },
      "protected": "eyJhbGciOiJSUzI1NiJ9",
      "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
    },
    {
      "header": {
        "kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"
      },
      "protected": "eyJhbGciOiJFUzI1NiJ9",
      "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
    }
  ]
}`
		buf, err := json.MarshalIndent(m, "", "  ")
		require.NoError(t, err, `json.MarshalIndent should succeed`)
		require.Equal(t, expected, string(buf), `output should match`)
	})
}

// TestMessageUnmarshalJSONRejectsLiteralJSONProtected documents that the
// "protected" member of a JSON-form JWS must be a base64url-encoded UTF-8
// string per RFC 7515 §3. Earlier versions of Signature.UnmarshalJSON had
// a relaxed-probe shortcut: if the string value of "protected" started
// with `{`, the decoder treated the value as already-decoded JSON and
// skipped base64 decoding. That gave callers a non-conforming wire form
// for the same logically-equivalent message — useful for evading
// byte-exact JWS deduplication / replay caches and asymmetric with the
// flattened branch (which only base64-decodes). Removing the probe brings
// general-form parsing in line with both RFC 7515 and the flattened path.
func TestMessageUnmarshalJSONRejectsLiteralJSONProtected(t *testing.T) {
	const nonConforming = `{
  "payload": "aGVsbG8",
  "signatures": [
    {
      "protected": "{\"alg\":\"HS256\"}",
      "signature": "AAAA"
    }
  ]
}`
	var msg jws.Message
	err := json.Unmarshal([]byte(nonConforming), &msg)
	require.Error(t, err,
		`general-form JWS with literal-JSON "protected" must be rejected (RFC 7515 §3 requires base64url)`)
}
