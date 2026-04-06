package examples_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwt_sign_with_custom_base64_encoder() {
	const symmetricKey = "0123456789abcdef0123456789abcdef"

	token, err := jwt.NewBuilder().
		Subject("github.com/lestrrat-go/jwx").
		IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
		Build()
	if err != nil {
		fmt.Printf("failed to create token: %s\n", err)
		return
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), []byte(symmetricKey)), jwt.WithBase64Encoder(base64.URLEncoding))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	fmt.Println(string(signed))

	parsed, err := jwt.Parse(signed, jwt.WithKey(jwa.HS256(), []byte(symmetricKey)), jwt.WithBase64Encoder(base64.URLEncoding))
	if err != nil {
		fmt.Printf("failed to parse token: %s\n", err)
		return
	}

	if err := json.NewEncoder(os.Stdout).Encode(parsed); err != nil {
		fmt.Printf("failed to encode token: %s\n", err)
		return
	}

	if !jwt.Equal(token, parsed) {
		fmt.Printf("parsed token does not match original token\n")
		return
	}

	// OUTPUT:
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjIzMzQzMTIwMCwic3ViIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ==.qZu-ATTtmo9k1NedYgwwBzaEYEJA1Z6dlVzPpmzrrrw=
	// {"iat":233431200,"sub":"github.com/lestrrat-go/jwx"}
}
