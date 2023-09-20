package bench_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jws"
)

func BenchmarkJWS(b *testing.B) {
	const compactStr = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
	compactBuf := []byte(compactStr)
	compactRdr := bytes.NewReader(compactBuf)
	b.Run("Serialization", func(b *testing.B) {
		const jsonStr = `{
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
		jsonBuf := []byte(jsonStr)
		jsonRdr := bytes.NewReader(jsonBuf)

		b.Run("Compact", func(b *testing.B) {
			testcases := []Case{
				{
					Name: "jws.Parse",
					Test: func(b *testing.B) error {
						_, err := jws.Parse(compactBuf)
						return err
					},
				},
				{
					Name:      "jws.ParseString",
					SkipShort: true,
					Test: func(b *testing.B) error {
						_, err := jws.ParseString(compactStr)
						return err
					},
				},
				{
					Name:      "jws.ParseReader",
					SkipShort: true,
					Pretest: func(b *testing.B) error {
						_, err := compactRdr.Seek(0, 0)
						return err
					},
					Test: func(b *testing.B) error {
						_, err := jws.ParseReader(compactRdr)
						return err
					},
				},
			}
			for _, tc := range testcases {
				tc.Run(b)
			}
		})
		b.Run("JSON", func(b *testing.B) {
			m, _ := jws.Parse([]byte(jsonStr))
			testcases := []Case{
				{
					Name: "jws.Parse",
					Test: func(b *testing.B) error {
						_, err := jws.Parse(jsonBuf)
						return err
					},
				},
				{
					Name:      "jws.ParseString",
					SkipShort: true,
					Test: func(b *testing.B) error {
						_, err := jws.ParseString(jsonStr)
						return err
					},
				},
				{
					Name:      "jws.ParseReader",
					SkipShort: true,
					Pretest: func(b *testing.B) error {
						_, err := jsonRdr.Seek(0, 0)
						return err
					},
					Test: func(b *testing.B) error {
						_, err := jws.ParseReader(jsonRdr)
						return err
					},
				},
				{
					Name: "json.Marshal",
					Test: func(b *testing.B) error {
						_, err := json.Marshal(m)
						return err
					},
				},
			}
			for _, tc := range testcases {
				tc.Run(b)
			}
		})
	})
}
