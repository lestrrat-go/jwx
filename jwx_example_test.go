package jwx_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwe"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-jwx/jwt"
)

func ExampleJWT() {
	c := jwt.NewClaimSet()
	c.Set("sub", "123456789")
	c.Set("aud", "foo")
	c.Set("https://github.com/lestrrat", "me")

	buf, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		log.Printf("failed to generate JSON: %s", err)
		return
	}

	log.Printf("%s", buf)
	log.Printf("sub     -> '%s'", c.Get("sub").(string))
	log.Printf("aud     -> '%v'", c.Get("aud").([]string))
	log.Printf("private -> '%s'", c.Get("https://github.com/lestrrat").(string))
}

func ExampleJWK() {
	set, err := jwk.FetchHTTP("https://foobar.domain/jwk.json")
	if err != nil {
		log.Printf("failed to parse JWK: %s", err)
		return
	}

	// If you KNOW you have exactly one key, you can just
	// use set.Keys[0]
	keys := set.LookupKeyID("mykey")
	if len(keys) == 0 {
		log.Printf("failed to lookup key: %s", err)
		return
	}

	key, err := keys[0].Materialize()
	if err != nil {
		log.Printf("failed to create public key: %s", err)
		return
	}

	// Use key for jws.Verify() or whatever
	_ = key
}

func ExampleJWS() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}

	buf, err := jws.Sign([]byte("Lorem ipsum"), jwa.RS256, privkey)
	if err != nil {
		log.Printf("failed to created JWS message: %s", err)
		return
	}

	// When you received a JWS message, you can verify the signature
	// and grab the payload sent in the message in one go:
	verified, err := jws.Verify(buf, jwa.RS256, &privkey.PublicKey)
	if err != nil {
		log.Printf("failed to verify message: %s", err)
		return
	}

	log.Printf("signed message verified! -> %s", verified)
}

func ExampleJWE() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}

	payload := []byte("Lorem Ipsum")

	encrypted, err := jwe.Encrypt(payload, jwa.RSA1_5, &privkey.PublicKey, jwa.A128CBC_HS256, jwa.NoCompress)
	if err != nil {
		log.Printf("failed to encrypt payload: %s", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted, jwa.RSA1_5, privkey)
	if err != nil {
		log.Printf("failed to decrypt: %s", err)
		return
	}

	if string(decrypted) != "Lorem Ipsum" {
		log.Printf("WHAT?!")
		return
	}
}
