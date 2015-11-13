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

	c, err := NewAesCrypt(jwa.A128CBC_HS256)
	if err != nil {
		log.Printf("failed to create content encrypter: %s", err)
		return
	}

	k := NewRSAKeyEncrypt(jwa.RSA1_5, &privkey.PublicKey)
	kg := NewRandomKeyGenerate(c.KeySize())

	e := NewEncrypt(c, kg, k)
	msg, err := e.Encrypt([]byte("Lorem Ipsum"))
	if err != nil {
		log.Printf("failed to encrypt payload: %s", err)
		return
	}

	decrypted, err := DecryptMessage(msg, privkey)
	if err != nil {
		log.Printf("failed to decrypt: %s", err)
		return
	}

	if string(decrypted) != "Lorem Ipsum" {
		log.Printf("WHAT?!")
		return
	}
}
