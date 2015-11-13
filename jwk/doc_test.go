package jwk

import (
	"io/ioutil"
	"log"
	"net/http"
)

func ExampleParse() {
	res, err := http.Get("https://foobar.domain/json")
	if err != nil {
		log.Printf("failed to make HTTP request: %s", err)
		return
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("failed to read response body: %s", err)
		return
	}

	set, err := Parse(buf)
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

	// Assuming RsaPublicKey...
	key := keys[0].(*RsaPublicKey)

	pubkey, err := key.PublicKey()
	if err != nil {
		log.Printf("failed to generate public key: %s", err)
		return
	}
	// Use pubkey for jws.Verify() or whatever
	_ = pubkey
}