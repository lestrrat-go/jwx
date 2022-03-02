package bench_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwe"
)

func BenchmarkJWE(b *testing.B) {
	const s = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ`

	m, _ := jwe.Parse([]byte(s))
	js, _ := json.Marshal(m)

	var v interface{}

	b.Run("Serialization", func(b *testing.B) {
		b.Run("JSON", func(b *testing.B) {
			testcases := []Case{
				{
					Name: "json.Marshal",
					Test: func(b *testing.B) error {
						_, err := json.Marshal(m)
						return err
					},
				},
				{
					Name: "json.Unmarshal",
					Test: func(b *testing.B) error {
						return json.Unmarshal(js, &v)
					},
				},
			}
			for _, tc := range testcases {
				tc.Run(b)
			}
		})
	})
}
