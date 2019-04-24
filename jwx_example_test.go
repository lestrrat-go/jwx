package jwx_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

func ExampleJWT() {
	const aLongLongTimeAgo = 233431200

	t := jwt.New()
	t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/jwt`)
	t.Set(jwt.AudienceKey, `Golang Users`)
	t.Set(jwt.IssuedAtKey, time.Unix(aLongLongTimeAgo, 0))
	t.Set(`privateClaimKey`, `Hello, World!`)

	buf, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return
	}

	fmt.Printf("%s\n", buf)
	fmt.Printf("aud -> '%s'\n", t.Audience())
	fmt.Printf("iat -> '%s'\n", t.IssuedAt().Format(time.RFC3339))
	if v, ok := t.Get(`privateClaimKey`); ok {
		fmt.Printf("privateClaimKey -> '%s'\n", v)
	}
	fmt.Printf("sub -> '%s'\n", t.Subject())
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
