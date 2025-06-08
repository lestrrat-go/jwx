package jwk_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func BenchmarkRSAPublicKeyMarshal(b *testing.B) {
	rsakey, err := jwxtest.GenerateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	pubkey, err := jwk.PublicKeyOf(rsakey)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := json.Marshal(pubkey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRSAPrivateKeyMarshal(b *testing.B) {
	rsakey, err := jwxtest.GenerateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := json.Marshal(rsakey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkECDSAPublicKeyMarshal(b *testing.B) {
	eckey, err := jwxtest.GenerateEcdsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	pubkey, err := jwk.PublicKeyOf(eckey)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := json.Marshal(pubkey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkECDSAPrivateKeyMarshal(b *testing.B) {
	eckey, err := jwxtest.GenerateEcdsaJwk()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := json.Marshal(eckey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSymmetricKeyMarshal(b *testing.B) {
	symkey, err := jwxtest.GenerateSymmetricJwk()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := json.Marshal(symkey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOKPEd25519PublicKeyMarshal(b *testing.B) {
	ed25519key, err := jwxtest.GenerateEd25519Jwk()
	if err != nil {
		b.Fatal(err)
	}
	pubkey, err := jwk.PublicKeyOf(ed25519key)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := json.Marshal(pubkey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOKPEd25519PrivateKeyMarshal(b *testing.B) {
	ed25519key, err := jwxtest.GenerateEd25519Jwk()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := json.Marshal(ed25519key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOKPX25519PublicKeyMarshal(b *testing.B) {
	x25519key, err := jwxtest.GenerateX25519Jwk()
	if err != nil {
		b.Fatal(err)
	}
	pubkey, err := jwk.PublicKeyOf(x25519key)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := json.Marshal(pubkey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOKPX25519PrivateKeyMarshal(b *testing.B) {
	x25519key, err := jwxtest.GenerateX25519Jwk()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := json.Marshal(x25519key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSetMultipleKeysMarshal(b *testing.B) {
	set := jwk.NewSet()

	// Add RSA key
	rsakey, err := jwxtest.GenerateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	if err := set.AddKey(rsakey); err != nil {
		b.Fatal(err)
	}

	// Add ECDSA key
	eckey, err := jwxtest.GenerateEcdsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	if err := set.AddKey(eckey); err != nil {
		b.Fatal(err)
	}

	// Add Symmetric key
	symkey, err := jwxtest.GenerateSymmetricJwk()
	if err != nil {
		b.Fatal(err)
	}
	if err := set.AddKey(symkey); err != nil {
		b.Fatal(err)
	}

	// Add Ed25519 key
	ed25519key, err := jwxtest.GenerateEd25519Jwk()
	if err != nil {
		b.Fatal(err)
	}
	if err := set.AddKey(ed25519key); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := json.Marshal(set); err != nil {
			b.Fatal(err)
		}
	}
}
