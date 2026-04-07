package jwe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

func BenchmarkEncryptKey(b *testing.B) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		b.Fatal(err)
	}

	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit")

	testcases := []struct {
		name string
		alg  jwa.KeyEncryptionAlgorithm
		enc  jwa.ContentEncryptionAlgorithm
		key  any
	}{
		{
			name: "RSA-OAEP",
			alg:  jwa.RSA_OAEP(),
			enc:  jwa.A256GCM(),
			key:  &rsaKey.PublicKey,
		},
		{
			name: "ECDH-ES",
			alg:  jwa.ECDH_ES(),
			enc:  jwa.A256GCM(),
			key:  &ecKey.PublicKey,
		},
		{
			name: "A256KW",
			alg:  jwa.A256KW(),
			enc:  jwa.A256GCM(),
			key:  symKey,
		},
	}

	for _, tc := range testcases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, err := Encrypt(payload,
					WithKey(tc.alg, tc.key),
					WithContentEncryption(tc.enc),
				)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecryptKey(b *testing.B) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		b.Fatal(err)
	}

	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit")

	testcases := []struct {
		name   string
		alg    jwa.KeyEncryptionAlgorithm
		enc    jwa.ContentEncryptionAlgorithm
		encKey any
		decKey any
	}{
		{
			name:   "RSA-OAEP",
			alg:    jwa.RSA_OAEP(),
			enc:    jwa.A256GCM(),
			encKey: &rsaKey.PublicKey,
			decKey: rsaKey,
		},
		{
			name:   "ECDH-ES",
			alg:    jwa.ECDH_ES(),
			enc:    jwa.A256GCM(),
			encKey: &ecKey.PublicKey,
			decKey: ecKey,
		},
		{
			name:   "A256KW",
			alg:    jwa.A256KW(),
			enc:    jwa.A256GCM(),
			encKey: symKey,
			decKey: symKey,
		},
	}

	for _, tc := range testcases {
		b.Run(tc.name, func(b *testing.B) {
			encrypted, err := Encrypt(payload,
				WithKey(tc.alg, tc.encKey),
				WithContentEncryption(tc.enc),
			)
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, err := Decrypt(encrypted, WithKey(tc.alg, tc.decKey))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
