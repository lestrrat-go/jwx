package comparison

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	golangJwtRSAKey     *rsa.PrivateKey
	golangJwtHMACKey    []byte
	golangJwtToken      string
	golangJwtTokenRS256 string
)

func init() {
	// Generate RSA key for testing
	var err error
	golangJwtRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Generate HMAC key
	golangJwtHMACKey = make([]byte, 32)
	if _, err := rand.Read(golangJwtHMACKey); err != nil {
		panic(err)
	}

	// Pre-generate tokens for parsing benchmarks
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	// HS256 token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	golangJwtToken, err = token.SignedString(golangJwtHMACKey)
	if err != nil {
		panic(err)
	}

	// RS256 token
	tokenRS := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	golangJwtTokenRS256, err = tokenRS.SignedString(golangJwtRSAKey)
	if err != nil {
		panic(err)
	}
}

func BenchmarkGolangJWT_SignHS256(b *testing.B) {
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	b.ResetTimer()
	for range b.N {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		_, err := token.SignedString(golangJwtHMACKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGolangJWT_SignRS256(b *testing.B) {
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	b.ResetTimer()
	for range b.N {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		_, err := token.SignedString(golangJwtRSAKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGolangJWT_ParseHS256(b *testing.B) {
	b.ResetTimer()
	for range b.N {
		token, err := jwt.Parse(golangJwtToken, func(_ *jwt.Token) (any, error) {
			return golangJwtHMACKey, nil
		})
		if err != nil {
			b.Fatal(err)
		}
		if !token.Valid {
			b.Fatal("token is not valid")
		}
	}
}

func BenchmarkGolangJWT_ParseRS256(b *testing.B) {
	b.ResetTimer()
	for range b.N {
		token, err := jwt.Parse(golangJwtTokenRS256, func(_ *jwt.Token) (any, error) {
			return &golangJwtRSAKey.PublicKey, nil
		})
		if err != nil {
			b.Fatal(err)
		}
		if !token.Valid {
			b.Fatal("token is not valid")
		}
	}
}

func BenchmarkGolangJWT_ParseWithClaims(b *testing.B) {
	claims := &jwt.MapClaims{}

	b.ResetTimer()
	for range b.N {
		token, err := jwt.ParseWithClaims(golangJwtToken, claims, func(_ *jwt.Token) (any, error) {
			return golangJwtHMACKey, nil
		})
		if err != nil {
			b.Fatal(err)
		}
		if !token.Valid {
			b.Fatal("token is not valid")
		}
	}
}

func BenchmarkGolangJWT_CreateAndParseHS256(b *testing.B) {
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	b.ResetTimer()
	for range b.N {
		// Create token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(golangJwtHMACKey)
		if err != nil {
			b.Fatal(err)
		}

		// Parse token
		parsedToken, err := jwt.Parse(tokenString, func(_ *jwt.Token) (any, error) {
			return golangJwtHMACKey, nil
		})
		if err != nil {
			b.Fatal(err)
		}
		if !parsedToken.Valid {
			b.Fatal("token is not valid")
		}
	}
}
