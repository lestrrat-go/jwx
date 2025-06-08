package jwt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func BenchmarkJWTParsing(b *testing.B) {
	// Generate RSA key for testing
	rsaKey, err := jwxtest.GenerateRsaJwk()
	if err != nil {
		b.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a token with some claims
	token := jwt.New()
	if err := token.Set(jwt.IssuerKey, "https://example.com"); err != nil {
		b.Fatalf("Failed to set issuer: %v", err)
	}
	if err := token.Set(jwt.SubjectKey, "test-subject"); err != nil {
		b.Fatalf("Failed to set subject: %v", err)
	}
	if err := token.Set(jwt.AudienceKey, []string{"audience1", "audience2"}); err != nil {
		b.Fatalf("Failed to set audience: %v", err)
	}
	if err := token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)); err != nil {
		b.Fatalf("Failed to set expiration: %v", err)
	}
	if err := token.Set(jwt.IssuedAtKey, time.Now()); err != nil {
		b.Fatalf("Failed to set issued at: %v", err)
	}
	if err := token.Set(jwt.NotBeforeKey, time.Now().Add(-time.Minute)); err != nil {
		b.Fatalf("Failed to set not before: %v", err)
	}

	// Add custom claims to make the token more realistic
	const numCustomClaims = 10
	for i := range numCustomClaims {
		key := fmt.Sprintf("custom_claim_%d", i)
		value := fmt.Sprintf("custom_value_%d", i)
		if err := token.Set(key, value); err != nil {
			b.Fatalf("Failed to set custom claim %s: %v", key, err)
		}
	}

	// Sign the token
	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), rsaKey))
	if err != nil {
		b.Fatalf("Failed to sign token: %v", err)
	}

	b.Run("WithJWSVerification", func(b *testing.B) {
		for range b.N {
			if _, err := jwt.Parse(signedToken, jwt.WithKey(jwa.RS256(), rsaKey)); err != nil {
				b.Fatalf("Failed to parse token with verification: %v", err)
			}
		}
	})

	b.Run("WithoutJWSVerification", func(b *testing.B) {
		for range b.N {
			if _, err := jwt.ParseInsecure(signedToken); err != nil {
				b.Fatalf("Failed to parse token without verification: %v", err)
			}
		}
	})
}
