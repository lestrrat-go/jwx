package jws

import (
	"crypto/rand"
	"crypto/rsa"
	"log"

	"github.com/lestrrat/go-jwx/jwa"
)

func ExampleSign_JWSCompact() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to create private key: %s", err)
		return
	}

	buf, err := Sign([]byte("Lorem ipsum"), jwa.RS256, privkey)
	if err != nil {
		log.Printf("failed to sign payload: %s", err)
		return
	}

	log.Printf("%s", buf)

	verified, err := Verify(buf, jwa.RS256, &privkey.PublicKey)
	if err != nil {
		log.Printf("failed to verify JWS message: %s", err)
		return
	}
	log.Printf("message verified!")

	// Do something with `verified` ....
	_ = verified
}

func ExampleSign_JWSJSON() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to create private key: %s", err)
		return
	}

	rsasign, err := NewRsaSign(jwa.RS256, privkey)
	if err != nil {
		log.Printf("failed to create RSA signer: %s", err)
		return
	}

	ps := []PayloadSigner{rsasign}
	s := NewMultiSign(ps...)

	payload := "Lorem ipsum"

	msg, err := s.Sign([]byte(payload))
	if err != nil {
		log.Printf("failed to sign payload: %s", err)
		return
	}

	buf, err := JSONSerialize{}.Serialize(msg)
	if err != nil {
		log.Printf("failed to serialize signed message: %s", err)
		return
	}

	verified, err := Verify(buf, jwa.RS256, &privkey.PublicKey)
	if err != nil {
		log.Printf("failed to verify JWS message: %s", err)
		return
	}
	log.Printf("message verified!")

	// Do something with `verified` ....
	_ = verified
}
