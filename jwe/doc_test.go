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

	k, err := NewRSAPKCSKeyEncrypt(jwa.RSA1_5, &privkey.PublicKey)
	if err != nil {
		log.Printf("failed to create key encrypter: %s", err)
		return
	}
	kg := NewRandomKeyGenerate(c.KeySize())

	e := NewMultiEncrypt(c, kg, k)
	msg, err := e.Encrypt([]byte("Lorem Ipsum"))
	if err != nil {
		log.Printf("failed to encrypt payload: %s", err)
		return
	}

	decrypted, err := DecryptMessage(msg, jwa.RSA1_5, privkey)
	if err != nil {
		log.Printf("failed to decrypt: %s", err)
		return
	}

	if string(decrypted) != "Lorem Ipsum" {
		log.Printf("WHAT?!")
		return
	}
}
