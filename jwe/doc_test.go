package jwe

import (
	"crypto/rand"
	"crypto/rsa"
	"log"

	"github.com/lestrrat/go-jwx/jwa"
)

func ExampleEncrypt() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}

	payload := []byte("Lorem Ipsum")

	encrypted, err := Encrypt(payload, jwa.RSA1_5, &privkey.PublicKey, jwa.A128CBC_HS256, jwa.NoCompress)
	if err != nil {
		log.Printf("failed to encrypt payload: %s", err)
		return
	}

	decrypted, err := Decrypt(encrypted, jwa.RSA1_5, privkey)
	if err != nil {
		log.Printf("failed to decrypt: %s", err)
		return
	}

	if string(decrypted) != "Lorem Ipsum" {
		log.Printf("WHAT?!")
		return
	}
}
