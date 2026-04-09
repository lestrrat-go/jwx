package jwk_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// BenchmarkImport measures the cost of converting raw Go crypto keys to JWK keys.
func BenchmarkImport(b *testing.B) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	symKey := []byte("symmetric-key-value-for-benchmark")

	b.Run("RSAPrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Import[jwk.RSAPrivateKey](rsaPriv); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RSAPublicKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Import[jwk.RSAPublicKey](&rsaPriv.PublicKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ECDSAPrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Import[jwk.ECDSAPrivateKey](ecPriv); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ECDSAPublicKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Import[jwk.ECDSAPublicKey](&ecPriv.PublicKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Ed25519PrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Import[jwk.OKPPrivateKey](edPriv); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Ed25519PublicKey", func(b *testing.B) {
		edPub := edPriv.Public().(ed25519.PublicKey)
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Import[jwk.OKPPublicKey](edPub); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("X25519PrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Import[jwk.OKPPrivateKey](x25519Priv); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SymmetricKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Import[jwk.SymmetricKey](symKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkExport measures the cost of converting JWK keys back to raw Go crypto keys.
func BenchmarkExport(b *testing.B) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	rsaJWK, err := jwk.Import[jwk.RSAPrivateKey](rsaPriv)
	if err != nil {
		b.Fatal(err)
	}
	rsaPubJWK, err := jwk.Import[jwk.RSAPublicKey](&rsaPriv.PublicKey)
	if err != nil {
		b.Fatal(err)
	}

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ecJWK, err := jwk.Import[jwk.ECDSAPrivateKey](ecPriv)
	if err != nil {
		b.Fatal(err)
	}
	ecPubJWK, err := jwk.Import[jwk.ECDSAPublicKey](&ecPriv.PublicKey)
	if err != nil {
		b.Fatal(err)
	}

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	edJWK, err := jwk.Import[jwk.OKPPrivateKey](edPriv)
	if err != nil {
		b.Fatal(err)
	}
	edPubJWK, err := jwk.Import[jwk.OKPPublicKey](edPriv.Public().(ed25519.PublicKey))
	if err != nil {
		b.Fatal(err)
	}

	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	x25519JWK, err := jwk.Import[jwk.OKPPrivateKey](x25519Priv)
	if err != nil {
		b.Fatal(err)
	}

	symJWK, err := jwk.Import[jwk.SymmetricKey]([]byte("symmetric-key-value-for-benchmark"))
	if err != nil {
		b.Fatal(err)
	}

	b.Run("RSAPrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Export[*rsa.PrivateKey](rsaJWK); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RSAPublicKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Export[*rsa.PublicKey](rsaPubJWK); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ECDSAPrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Export[*ecdsa.PrivateKey](ecJWK); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ECDSAPublicKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Export[*ecdsa.PublicKey](ecPubJWK); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ECDSAPublicKey/ECDH", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Export[*ecdh.PublicKey](ecPubJWK); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("OKPPrivateKey/Ed25519", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Export[ed25519.PrivateKey](edJWK); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("OKPPublicKey/Ed25519", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Export[ed25519.PublicKey](edPubJWK); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("OKPPrivateKey/X25519", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Export[*ecdh.PrivateKey](x25519JWK); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SymmetricKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := jwk.Export[[]byte](symJWK); err != nil {
				b.Fatal(err)
			}
		}
	})
}
