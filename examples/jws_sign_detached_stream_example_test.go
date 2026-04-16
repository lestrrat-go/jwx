package examples_test

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func Example_jws_sign_detached_stream() {
	// This example demonstrates how to sign a detached payload
	// provided as an io.Reader, without loading the entire payload
	// into memory. This is useful when the payload is too large to
	// fit in memory.

	// Generate a random payload. In real use, the payload would be an
	// io.Reader that doesn't require full materialization, such as
	// os.Open("largefile") or an http.Response.Body.
	payload := make([]byte, 1024*1024) // 1 MB
	if _, err := rand.Read(payload); err != nil {
		fmt.Printf("failed to generate payload: %s\n", err)
		return
	}

	// Create a symmetric key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	// Sign by streaming the payload through the hash function.
	// The payload is read from an io.Reader and never fully buffered.
	// The result is a compact JWS with an empty payload segment.
	signed, err := jws.SignDetachedReader(bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	// Verify by streaming the payload through the hash function.
	err = jws.VerifyDetachedReader(signed, bytes.NewReader(payload), jws.WithKey(jwa.HS256(), key))
	if err != nil {
		fmt.Printf("failed to verify: %s\n", err)
		return
	}

	fmt.Println("sign and verify successful")
	// OUTPUT:
	// sign and verify successful
}
