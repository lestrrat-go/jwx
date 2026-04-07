package jwe

import (
	"bytes"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/tokens"
)

var s = []byte(`eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ`)

func BenchmarkSplitLib(b *testing.B) {
	for b.Loop() {
		SplitLib(s)
	}
}

func BenchmarkSplitManual(b *testing.B) {
	ret := make([][]byte, 5)
	for b.Loop() {
		SplitManual(ret, s)
	}
}

func SplitLib(buf []byte) [][]byte {
	return bytes.Split(buf, []byte{tokens.Period})
}

func SplitManual(parts [][]byte, buf []byte) {
	bufi := 0
	for len(buf) > 0 {
		i := bytes.IndexByte(buf, tokens.Period)
		if i == -1 {
			return
		}

		parts[bufi] = buf[:i]
		bufi++
		if len(buf) > i {
			buf = buf[i+1:]
		}
		if bufi == 4 {
			break
		}
	}

	if bytes.Contains(buf, []byte{tokens.Period}) {
		return
	}

	parts[4] = buf
}
