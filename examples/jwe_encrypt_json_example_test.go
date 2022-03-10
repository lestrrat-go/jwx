package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWE_EncryptJSON() {
	rawprivkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to create raw private key: %s\n", err)
		return
	}
	privkey, err := jwk.FromRaw(rawprivkey)
	if err != nil {
		fmt.Printf("failed to create private key: %s\n", err)
		return
	}

	pubkey, err := privkey.PublicKey()
	if err != nil {
		fmt.Printf("failed to create public key:%s\n", err)
		return
	}

	const payload = `Lorem ipsum`
	encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithJSON(), jwe.WithKey(jwa.RSA_OAEP, pubkey))
	if err != nil {
		fmt.Printf("failed to encrypt payload: %s\n", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, privkey))
	if err != nil {
		fmt.Printf("failed to decrypt payload: %s\n", err)
		return
	}
	fmt.Printf("%s\n", decrypted)
	// OUTPUT:
	// Lorem ipsum
}

//func ExampleJWE_EncryptJSON() {
//	var privkeys []jwk.Key
//	var pubkeys []jwk.Key
//
//	for i := 0; i < 3; i++ {
//		rawprivkey, err := rsa.GenerateKey(rand.Reader, 2048)
//		if err != nil {
//			fmt.Printf("failed to create raw private key: %s\n", err)
//			return
//		}
//		privkey, err := jwk.FromRaw(rawprivkey)
//		if err != nil {
//			fmt.Printf("failed to create private key: %s\n", err)
//			return
//		}
//		privkeys = append(privkeys, privkey)
//
//		pubkey, err := privkey.PublicKey()
//		if err != nil {
//			fmt.Printf("failed to create public key:%s\n", err)
//			return
//		}
//		pubkeys = append(pubkeys, pubkey)
//	}
//
//	options := []jwe.EncryptOption{jwe.WithJSON()}
//	for _, key := range pubkeys {
//		options = append(options, jwe.WithKey(jwa.RSA_OAEP, key))
//		break
//	}
//
//	const payload = `Lorem ipsum`
//	encrypted, err := jwe.Encrypt([]byte(payload), options...)
//	if err != nil {
//		fmt.Printf("failed to encrypt payload: %s\n", err)
//		return
//	}
//
//	for i, key := range privkeys {
//		log.Printf("trying key %d", i)
//		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP, key))
//		if err != nil {
//			fmt.Printf("failed to decrypt payload: %s\n", err)
//			return
//		}
//		fmt.Printf("%s\n", decrypted)
//		break
//	}
//	// OUTPUT:
//}
