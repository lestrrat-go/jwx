package buffer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuffer_FromUint(t *testing.T) {
	b := FromUint(1)
	if !assert.Equal(t, []byte{1}, b.Bytes(), "should be left trimmed") {
		return
	}
}

func TestBuffer_Convert(t *testing.T) {
	v1 := []byte{'a', 'b', 'c'}
	b := Buffer(v1)

	if !assert.Equal(t, v1, b.Bytes()) {
		return
	}

	v2 := "abc"
	b = Buffer(v2)
	if !assert.Equal(t, []byte(v2), b.Bytes()) {
		return
	}

}

func TestBuffer_Base64Encode(t *testing.T) {
	b := Buffer{'a', 'b', 'c'}
	v, err := b.Base64Encode()
	if !assert.NoError(t, err, "Base64 encode is successful") {
		return
	}
	if !assert.Equal(t, []byte{'Y', 'W', 'J', 'j'}, v) {
		return
	}
}

func TestJSON(t *testing.T) {
	b1 := Buffer{'a', 'b', 'c'}

	jsontxt, err := json.Marshal(b1)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.Equal(t, `"YWJj"`, string(jsontxt)) {
		return
	}

	var b2 Buffer
	if !assert.NoError(t, json.Unmarshal(jsontxt, &b2)) {
		return
	}

	if !assert.Equal(t, b1, b2) {
		return
	}
}

func TestFunky(t *testing.T) {
	s := `QD4_B3ghg0PNu-c_EAlXn3Xlb0gzAFPJSYQSI1cZZ8sPIxISgPMtNJTzgncC281IaKDXLV1aEnYuH5eH-4u4f383zlyBCGKSKSQWmqKNE7xcIqleFVNsfzOucTL4QRxfbcyHcli_symC_RGWJ6GdocE0VgyYN8t9_0sm_Nq5lcwtYEQs_hNlf1ileCjjdsUfC05zTbbrLpMjgI3IK5_QxOU81FLei4LMx3iQ1kqrIGH5FxxQMKGdx_fDaRQ-YBAA2YVqn7rs3TcwQ7NUjjz8JyDE168NlMV1WxoDC9nwOe0O6K4NzFuWpoGHTh0M-0lT5M3dy9kEBYgPtWoe_u9dogA`
	b := Buffer{}
	if !assert.NoError(t, b.Base64Decode([]byte(s)), "Base64Decode should work") {
		return
	}

	if !assert.Equal(t, 257, b.Len(), "Should 257 bytes") {
		return
	}
}

func TestBuffer_NData(t *testing.T) {
	payload := []byte("Alice")
	nd := Buffer(payload).NData()
	if !assert.Equal(t, []byte{0, 0, 0, 5, 65, 108, 105, 99, 101}, nd, "NData mathces") {
		return
	}

	b1, err := FromNData(nd)
	if !assert.NoError(t, err, "FromNData succeeds") {
		return
	}

	if !assert.Equal(t, payload, b1.Bytes(), "payload matches") {
		return
	}
}
