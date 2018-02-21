package jws_test

import (
	"crypto/rand"
	"crypto/rsa"
	"log"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
)

func ExampleSign_JWSCompact() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to create private key: %s", err)
		return
	}

	buf, err := jws.Sign([]byte("Lorem ipsum"), jwa.RS256, privkey)
	if err != nil {
		log.Printf("failed to sign payload: %s", err)
		return
	}

	log.Printf("%s", buf)

	verified, err := jws.Verify(buf, jwa.RS256, &privkey.PublicKey)
	if err != nil {
		log.Printf("failed to verify JWS message: %s", err)
		return
	}
	log.Printf("message verified!")

	// Do something with `verified` ....
	_ = verified
}

func ExampleSign_JWSJSON() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to create private key: %s", err)
		return
	}

	payload := "Lorem ipsum"

	//TODO fix formatter
	buf, err := jws.Sign([]byte(payload), jwa.RS256, key)
	if err != nil {
		log.Printf("failed to sign payload: %s", err)
		return
	}

	verified, err := jws.Verify(buf, jwa.RS256, &key.PublicKey)
	if err != nil {
		log.Printf("failed to verify JWS message: %s", err)
		return
	}
	log.Printf("message verified!")

	// Do something with `verified` ....
	_ = verified
}
