package jwe_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte(`eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_.XFBoMYUZodetZdvTiFvSkQ`))
	f.Add([]byte(`{"protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","encrypted_key":"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe","iv":"48V1_ALb6US04U3b","ciphertext":"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_","tag":"XFBoMYUZodetZdvTiFvSkQ"}`))
	f.Add([]byte(``))
	f.Add([]byte(`not-a-jwe`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = jwe.Parse(data)
	})
}

func FuzzEncryptAndDecrypt(f *testing.F) {
	f.Add([]byte(`hello world`))
	f.Add([]byte(`The true sign of intelligence is not knowledge but imagination.`))
	f.Add([]byte(`{"key":"value"}`))

	// Use a symmetric key for fast encrypt/decrypt round-trips.
	rawKey := []byte(`0123456789abcdef`) // 128-bit key for A128KW
	key, err := jwk.Import[jwk.Key](rawKey)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) == 0 {
			return
		}

		encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.A128KW(), key))
		require.NoError(t, err)

		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), key))
		require.NoError(t, err)
		require.Equal(t, payload, decrypted)
	})
}
