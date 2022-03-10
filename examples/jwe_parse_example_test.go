package examples_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwe"
)

func ExampleJWE_Parse() {
	const src = `eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.KrFTaMKVY_iUKYYk905QjbUf_fpBXvXCzIAfbPoPMGViDzxtgz5qnch8waV7wraVDfzpW7JfPOw6Nz_-XRwN3Vbud48bRYFw92GkC0M6kpKFpl_xgZxGN47ggNk9hzgqd7mFCuyufeYdn5c2fPoRZAV4UxvakLozEYcQo-eZaFmoYS4pyoC-IKKRikobW8n__LksMzXc_Vps1axn5kdpxsKQ4k1oayvUrgWX2PMxKn_TcLEKHtCN7qRlJ5hkKbZAXAdd34zGWcFV5gc1tcLs6HFhnebo8GUgItTYWBKSKzF6MyLJNRSUPFVq9q-Jxi1juXIlDrv_7rHVsdokQmBfvA.bK7z7Z3gEzFDgDQvNen0Ww.2hngnAVrmucUpJKLgIzYcg.CHs3ZP7JtG430Dl9YAKLMAl`

	msg, err := jwe.Parse([]byte(src))
	if err != nil {
		fmt.Printf("failed to parse JWE message: %s\n", err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(msg)
	// OUTPUT:
	// {"ciphertext":"2hngnAVrmucUpJKLgIzYcg","encrypted_key":"KrFTaMKVY_iUKYYk905QjbUf_fpBXvXCzIAfbPoPMGViDzxtgz5qnch8waV7wraVDfzpW7JfPOw6Nz_-XRwN3Vbud48bRYFw92GkC0M6kpKFpl_xgZxGN47ggNk9hzgqd7mFCuyufeYdn5c2fPoRZAV4UxvakLozEYcQo-eZaFmoYS4pyoC-IKKRikobW8n__LksMzXc_Vps1axn5kdpxsKQ4k1oayvUrgWX2PMxKn_TcLEKHtCN7qRlJ5hkKbZAXAdd34zGWcFV5gc1tcLs6HFhnebo8GUgItTYWBKSKzF6MyLJNRSUPFVq9q-Jxi1juXIlDrv_7rHVsdokQmBfvA","header":{"alg":"RSA1_5"},"iv":"bK7z7Z3gEzFDgDQvNen0Ww","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","tag":"CHs3ZP7JtG430Dl9YAKLMAk"}
}
