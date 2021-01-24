package bench_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/jws"
)

func runJWSBench(b *testing.B, name string, fn func()) {
	b.Helper()
	b.Run(name, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fn()
		}
	})
}

func BenchmarkJWS(b *testing.B) {
	b.Run("Serialization", func(b *testing.B) {
		const compactStr = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
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
		compactBuf := []byte(compactStr)

		b.Run("Compact", func(b *testing.B) {
			testcases := map[string]func(){
				"jws.Parse":       func() { _, _ = jws.Parse(compactBuf) },
				"jws.ParseString": func() { _, _ = jws.ParseString(compactStr) },
			}
			for name, tc := range testcases {
				name := name
				tc := tc
				runJWSBench(b, name, tc)
			}
		})
		b.Run("JSON", func(b *testing.B) {
			m, _ := jws.Parse([]byte(jsonStr))
			testcases := map[string]func(){
				"jws.Parse":       func() { _, _ = jws.Parse(jsonBuf) },
				"jws.ParseString": func() { _, _ = jws.ParseString(jsonStr) },
				"json.Marshal":    func() { _, _ = json.Marshal(m) },
			}
			for name, tc := range testcases {
				name := name
				tc := tc
				runJWSBench(b, name, tc)
			}
		})
	})
}
