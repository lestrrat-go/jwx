package comparison

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var (
	jwxRSAKey     jwk.Key
	jwxHMACKey    jwk.Key
	jwxToken      []byte
	jwxTokenRS256 []byte
)

func init() {
	// Generate RSA key for testing
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	jwxRSAKey, err = jwk.Import(rsaKey)
	if err != nil {
		panic(err)
	}

	// Generate HMAC key
	hmacKeyBytes := make([]byte, 32)
	if _, err := rand.Read(hmacKeyBytes); err != nil {
		panic(err)
	}

	jwxHMACKey, err = jwk.Import(hmacKeyBytes)
	if err != nil {
		panic(err)
	}

	// Pre-generate tokens for parsing benchmarks
	tok := jwt.New()
	tok.Set(jwt.SubjectKey, "1234567890")
	tok.Set("name", "John Doe")
	tok.Set(jwt.IssuedAtKey, time.Now())
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))

	// HS256 token
	jwxToken, err = jwt.Sign(tok, jwt.WithKey(jwa.HS256(), jwxHMACKey))
	if err != nil {
		panic(err)
	}

	// RS256 token
	jwxTokenRS256, err = jwt.Sign(tok, jwt.WithKey(jwa.RS256(), jwxRSAKey))
	if err != nil {
		panic(err)
	}
}

func BenchmarkJWX_JWTSignHS256(b *testing.B) {
	tok := jwt.New()
	tok.Set(jwt.SubjectKey, "1234567890")
	tok.Set("name", "John Doe")
	tok.Set(jwt.IssuedAtKey, time.Now())
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	options := []jwt.SignOption{jwt.WithKey(jwa.HS256(), jwxHMACKey)}
	b.ResetTimer()
	for range b.N {
		_, err := jwt.Sign(tok, options...)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWX_JWTSignRS256(b *testing.B) {
	tok := jwt.New()
	tok.Set(jwt.SubjectKey, "1234567890")
	tok.Set("name", "John Doe")
	tok.Set(jwt.IssuedAtKey, time.Now())
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	options := []jwt.SignOption{jwt.WithKey(jwa.RS256(), jwxRSAKey)}
	b.ResetTimer()
	for range b.N {
		_, err := jwt.Sign(tok, options...)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWX_JWTParseHS256(b *testing.B) {
	options := []jwt.ParseOption{jwt.WithKey(jwa.HS256(), jwxHMACKey)}
	b.ResetTimer()
	for range b.N {
		_, err := jwt.Parse(jwxToken, options...)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWX_JWTParseRS256(b *testing.B) {
	publicKey, err := jwxRSAKey.PublicKey()
	if err != nil {
		b.Fatal(err)
	}
	options := []jwt.ParseOption{jwt.WithKey(jwa.RS256(), publicKey)}

	b.ResetTimer()
	for range b.N {
		_, err := jwt.Parse(jwxTokenRS256, options...)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWX_JWTParseWithValidation(b *testing.B) {
	options := []jwt.ParseOption{jwt.WithKey(jwa.HS256(), jwxHMACKey), jwt.WithValidate(true)}
	b.ResetTimer()
	for range b.N {
		_, err := jwt.Parse(jwxToken, options...)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWX_CreateAndParseHS256(b *testing.B) {
	tok := jwt.New()
	tok.Set(jwt.SubjectKey, "1234567890")
	tok.Set("name", "John Doe")
	tok.Set(jwt.IssuedAtKey, time.Now())
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))

	b.ResetTimer()
	signoptions := []jwt.SignOption{jwt.WithKey(jwa.HS256(), jwxHMACKey)}
	parseoptions := []jwt.ParseOption{jwt.WithKey(jwa.HS256(), jwxHMACKey)}
	for range b.N {
		// Create token
		tokenBytes, err := jwt.Sign(tok, signoptions...)
		if err != nil {
			b.Fatal(err)
		}

		// Parse token
		_, err = jwt.Parse(tokenBytes, parseoptions...)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWX_JWSSignHS256(b *testing.B) {
	payload := []byte(`{"sub":"1234567890","name":"John Doe","iat":1516239022}`)
	options := []jws.SignOption{jws.WithKey(jwa.HS256(), jwxHMACKey)}
	b.ResetTimer()
	for range b.N {
		_, err := jws.Sign(payload, options...)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWX_JWSParseHS256(b *testing.B) {
	payload := []byte(`{"sub":"1234567890","name":"John Doe","iat":1516239022}`)
	signoptions := []jws.SignOption{jws.WithKey(jwa.HS256(), jwxHMACKey)}
	signature, err := jws.Sign(payload, signoptions...)
	if err != nil {
		b.Fatal(err)
	}

	parseoptions := []jws.VerifyOption{jws.WithKey(jwa.HS256(), jwxHMACKey)}
	b.ResetTimer()
	for range b.N {
		_, err := jws.Verify(signature, parseoptions...)
		if err != nil {
			b.Fatal(err)
		}
	}
}
