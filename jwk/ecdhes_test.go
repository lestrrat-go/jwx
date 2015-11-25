package jwk

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/stretchr/testify/assert"
)

func TestECDHES_KeyAgreement(t *testing.T) {
	prodkeysrc := `{"kty":"EC",
      "crv":"P-256",
      "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
      "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
      "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
     }`
	conskeysrc := `{"kty":"EC",
      "crv":"P-256",
      "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
      "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
      "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
     }`
	apusrc := []byte(`Alice`)
	apvsrc := []byte(`Bob`)
	epksrc := `{"alg":"ECDH-ES",
      "enc":"A128GCM",
      "apu":"QWxpY2U",
      "apv":"Qm9i",
      "epk":
       {"kty":"EC",
        "crv":"P-256",
        "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
        "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
       }
     }`

	prodkey, err := ParseString(prodkeysrc)
	if !assert.NoError(t, err, "producer key parsed successfully") {
		return
	}

	privkey, err := prodkey.Keys[0].(*EcdsaPrivateKey).PrivateKey()
	if !assert.NoError(t, err, "got private key") {
		return
	}

	k := NewEcdhesPublicKey(&privkey.PublicKey, jwa.ECDH_ES, jwa.A128GCM, apusrc, apvsrc)
	jsonbuf, _ := json.MarshalIndent(k, "", "  ")
	t.Logf("%s", jsonbuf)
	_ = k
	_ = conskeysrc
	_ = epksrc
}
